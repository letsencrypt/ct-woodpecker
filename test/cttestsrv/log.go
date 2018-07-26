package cttestsrv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctfe "github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/log"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/memory"
	"github.com/google/trillian/trees"
	"github.com/google/trillian/types"

	_ "github.com/google/trillian/crypto/keys/der/proto" // PrivateKey proto handler
	_ "github.com/google/trillian/crypto/keys/pem/proto" // PEMKeyFile proto handler
	_ "github.com/google/trillian/merkle/rfc6962"        // Make hashers available
)

var (
	timeSource = util.SystemTimeSource{}
)

// a testTree bundles together in-memory storage, a trillian tree, a hasher and
// a sequencer. testTree's are maintained by a testLog and use the same private
// key. It is not safe to use concurrently without additional locking.
type testTree struct {
	logStorage storage.LogStorage
	tree       *trillian.Tree

	hasher    hashers.LogHasher
	sequencer *log.Sequencer
}

// a testLog is a CT log that maintains two in-memory testTrees. Only one
// testTree is active at a time. The active tree is used to produce STH's, to
// queue submitted leaves producing SCTs, and to integrate leaves to the log. By
// switching between active trees external users can make inconsistencies appear
// that should cause a functional ct-woodpecker monitor to increment error
// stats. It is not safe to use concurrently without additional locking.
type testLog struct {
	key *ecdsa.PrivateKey

	activeTree *testTree

	treeA *testTree
	treeB *testTree

	adminStorage storage.AdminStorage
}

// makeTree constructs a testTree with the given name/description and private
// key. The empty tree will be initialized with an initial STH.
func makeTree(name string, key *ecdsa.PrivateKey) (*testTree, error) {
	keyBytes, err := der.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}

	pk, err := ptypes.MarshalAny(&keyspb.PrivateKey{
		Der: keyBytes,
	})
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	tree := &trillian.Tree{
		TreeId:             0,
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        name,
		Description:        "An in-memory ct-test-srv testTree",
		PrivateKey:         pk,
		PublicKey: &keyspb.PublicKey{
			Der: pubKeyBytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}

	hasher, err := hashers.NewLogHasher(tree.HashStrategy)
	if err != nil {
		return nil, err
	}

	signer, err := trees.Signer(context.Background(), tree)
	if err != nil {
		return nil, err
	}

	logStorage := memory.NewLogStorage(nil)
	adminStorage := memory.NewAdminStorage(logStorage)

	sequencer := log.NewSequencer(hasher, timeSource, logStorage, signer, nil, quota.Noop())

	// overwrite the tree with the one returned from CreateTree since it will populate a TreeId
	tree, err = storage.CreateTree(context.Background(), adminStorage, tree)
	if err != nil {
		return nil, err
	}

	tt := &testTree{
		tree:       tree,
		logStorage: logStorage,
		hasher:     hasher,
		sequencer:  sequencer,
	}

	// initialize the tree with an empty STH
	if err := initSTH(tt); err != nil {
		return nil, err
	}

	return tt, nil
}

// initSTH initializes a tree with an empty tree STH.
func initSTH(tt *testTree) error {
	signer, err := trees.Signer(context.Background(), tt.tree)
	if err != nil {
		return err
	}

	// init the new tree by signing a STH for the empty root
	root, err := signer.SignLogRoot(&types.LogRootV1{
		RootHash:       tt.hasher.EmptyRoot(),
		TimestampNanos: uint64(timeSource.Now().UnixNano()),
	})
	if err != nil {
		return err
	}

	// store the new STH
	err = tt.logStorage.ReadWriteTransaction(context.Background(), tt.tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		return tx.StoreSignedLogRoot(ctx, *root)
	})
	if err != nil {
		return err
	}

	return nil
}

// newLog creates a new testLog with the given private key.
func newLog(key *ecdsa.PrivateKey) (*testLog, error) {
	treeA, err := makeTree("treeA", key)
	if err != nil {
		return nil, err
	}
	treeB, err := makeTree("treeB", key)
	if err != nil {
		return nil, err
	}

	return &testLog{
		activeTree: treeA,
		treeA:      treeA,
		treeB:      treeB,

		key: key,
	}, nil
}

// switchTrees toggles the active tree between treeA and treeB.
// It returns the new active tree.
func (log *testLog) switchTrees() *testTree {
	if log.activeTree == log.treeA {
		log.activeTree = log.treeB
	} else {
		log.activeTree = log.treeA
	}
	return log.activeTree
}

// getProof gets a trillian consistency proof between the first and second tree
// sizes, or returns an error. Minimal request parameter validation is done.
func (log *testLog) getProof(first, second int64) (*trillian.GetConsistencyProofResponse, error) {
	tx, err := log.activeTree.logStorage.SnapshotForTree(context.Background(), log.activeTree.tree)
	defer func() { _ = tx.Close() }()

	if err != nil {
		return nil, err
	}

	slr, err := tx.LatestSignedLogRoot(context.Background())
	if err != nil {
		return nil, err
	}
	var root types.LogRootV1
	if err := root.UnmarshalBinary(slr.LogRoot); err != nil {
		return nil, err
	}

	if first < 1 || first > int64(root.TreeSize) {
		return nil, fmt.Errorf("Illegal first value: %d", first)
	}

	if second < 1 || second < first || second > int64(root.TreeSize) {
		return nil, fmt.Errorf("Illegal second value: %d", second)
	}

	nodeFetches, err := merkle.CalcConsistencyProofNodeAddresses(first, second, int64(root.TreeSize), 64)
	if err != nil {
		return nil, err
	}

	proof, err := fetchNodesAndBuildProof(context.Background(), tx, log.activeTree.hasher, tx.ReadRevision(), 0, nodeFetches)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	resp := &trillian.GetConsistencyProofResponse{
		SignedLogRoot: &slr,
		Proof:         &proof,
	}
	return resp, nil
}

// getSTH returns the signed tree head for the currently active testlog tree.
func (log *testLog) getSTH() (*ct.SignedTreeHead, error) {
	tx, err := log.activeTree.logStorage.SnapshotForTree(context.Background(), log.activeTree.tree)
	defer func() { _ = tx.Close() }()

	if err != nil {
		return nil, err
	}

	signedLogRoot, err := tx.LatestSignedLogRoot(context.Background())
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	sth := ct.SignedTreeHead{
		Version:   ct.V1,
		TreeSize:  uint64(signedLogRoot.TreeSize),
		Timestamp: uint64(signedLogRoot.TimestampNanos / 1000 / 1000),
	}
	copy(sth.SHA256RootHash[:], signedLogRoot.RootHash)

	sthBytes, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(sthBytes)
	signature, err := log.key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(log.key.Public()),
		},
		Signature: signature,
	}
	return &sth, nil
}

// addChain queues a chain of ct.ASN1Certs (or precerts) to the currently active
// testLog tree and returns a SCT for the submission or an error.
func (log *testLog) addChain(chain []ct.ASN1Cert, precert bool) (*ct.SignedCertificateTimestamp, error) {
	entryType := ct.X509LogEntryType
	if precert {
		entryType = ct.PrecertLogEntryType
	}

	now := timeSource.Now()
	timeMillis := uint64(now.UnixNano() / (1000 * 1000))
	leaf, err := ct.MerkleTreeLeafFromRawChain(chain, entryType, timeMillis)
	if err != nil {
		return nil, err
	}

	logLeaf, err := util.BuildLogLeaf("ct-test-srv", *leaf, 0, chain[0], chain[1:], precert)
	if err != nil {
		return nil, err
	}

	leafHash, err := log.activeTree.hasher.HashLeaf(logLeaf.LeafValue)
	if err != nil {
		return nil, err
	}
	logLeaf.MerkleLeafHash = leafHash
	logLeaf.LeafIdentityHash = logLeaf.MerkleLeafHash

	leaves := []*trillian.LogLeaf{&logLeaf}
	queuedLeaves, err := log.activeTree.logStorage.QueueLeaves(context.Background(), log.activeTree.tree, leaves, now)
	if err != nil {
		return nil, err
	}

	if len(queuedLeaves) != 1 {
		return nil, fmt.Errorf("called QueueLeaves with 1 leaf, got back %d", len(queuedLeaves))
	}

	queuedLeaf := queuedLeaves[0]
	var loggedLeaf ct.MerkleTreeLeaf
	rest, err := cttls.Unmarshal(queuedLeaf.Leaf.LeafValue, &loggedLeaf)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unmarshaling logged leaf left %d bytes unaccounted for", len(rest))
	}

	tbsSCT := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  loggedLeaf.TimestampedEntry.Timestamp,
		Extensions: loggedLeaf.TimestampedEntry.Extensions,
	}

	tbsSCTBytes, err := ct.SerializeSCTSignatureInput(tbsSCT, ct.LogEntry{Leaf: loggedLeaf})
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(tbsSCTBytes)
	signature, err := log.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	ds := ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(log.key.Public()),
		},
		Signature: signature,
	}

	logID, err := ctfe.GetCTLogID(log.key.Public())
	if err != nil {
		return nil, err
	}

	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: tbsSCT.SCTVersion,
		Timestamp:  tbsSCT.Timestamp,
		Extensions: tbsSCT.Extensions,
		LogID:      ct.LogID{KeyID: logID},
		Signature:  ds,
	}
	return sct, nil
}

// integrateBatch uses the currently active testLog's tree's sequencer to
// integrate up to `count` queued leaves. The number of queued leaves that was
// integrated is returned to the caller.
func (log *testLog) integrateBatch(count int64) (int, error) {
	maxRootDuration, err := ptypes.Duration(log.activeTree.tree.MaxRootDuration)
	if err != nil {
		return 0, err
	}
	integratedCount, err := log.activeTree.sequencer.IntegrateBatch(
		context.Background(),
		log.activeTree.tree,
		int(count),
		time.Duration(0),
		maxRootDuration)
	if err != nil {
		return 0, err
	}
	return integratedCount, nil
}

// signSTH uses the testlog's private key to sign a STH provided externally for
// use as a mock response.
func (log *testLog) signSTH(sth *ct.SignedTreeHead) error {
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(sthBytes)
	signature, err := log.key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(log.key.Public()),
		},
		Signature: signature,
	}

	return nil
}

// getEntries returns a slice of trillian.LogLeaf pointers between the provided
// start and end point of the tree.
func (log *testLog) getEntries(start, end int64) ([]*trillian.LogLeaf, error) {
	tx, err := log.activeTree.logStorage.SnapshotForTree(context.Background(), log.activeTree.tree)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Close() }()

	slr, err := tx.LatestSignedLogRoot(context.Background())
	if err != nil {
		return nil, err
	}
	var root types.LogRootV1
	if err := root.UnmarshalBinary(slr.LogRoot); err != nil {
		return nil, err
	}
	if start >= int64(root.TreeSize) {
		return nil, fmt.Errorf("start index %d is larger than tree size %d\n", start, root.TreeSize)
	}

	return tx.GetLeavesByRange(context.Background(), start, end-start)
}
