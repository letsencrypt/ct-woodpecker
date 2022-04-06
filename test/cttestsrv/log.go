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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctfe "github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/log"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/memory"
	"github.com/google/trillian/types"
	"github.com/google/trillian/util/clock"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	timeSource = clock.System
)

func init() {
	keys.RegisterHandler(&keyspb.PrivateKey{}, der.FromProto)
	keys.RegisterHandler(&keyspb.PEMKeyFile{}, pem.FromProto)
}

// a testTree bundles together in-memory storage, a trillian tree, a hasher and
// a sequencer. testTree's are maintained by a testLog and use the same private
// key. It is not safe to use concurrently without additional locking.
type testTree struct {
	logStorage storage.LogStorage
	tree       *trillian.Tree

	hasher hashers.LogHasher
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

	windowStart *time.Time
	windowEnd   *time.Time
}

// makeTree constructs a testTree with the given name/description and private
// key. The empty tree will be initialized with an initial STH.
func makeTree(name string, _ *ecdsa.PrivateKey) (*testTree, error) {
	tree := &trillian.Tree{
		TreeId:          0,
		TreeState:       trillian.TreeState_ACTIVE,
		TreeType:        trillian.TreeType_LOG,
		DisplayName:     name,
		Description:     "An in-memory ct-test-srv testTree",
		MaxRootDuration: durationpb.New(0),
	}

	treeStorage := memory.NewTreeStorage()
	logStorage := memory.NewLogStorage(treeStorage, monitoring.InertMetricFactory{})
	adminStorage := memory.NewAdminStorage(treeStorage)

	// overwrite the tree with the one returned from CreateTree since it will populate a TreeId
	tree, err := storage.CreateTree(context.Background(), adminStorage, tree)
	if err != nil {
		return nil, fmt.Errorf("creating tree: %w", err)
	}

	tt := &testTree{
		tree:       tree,
		hasher:     rfc6962.DefaultHasher,
		logStorage: logStorage,
	}

	// initialize the tree with an empty STH
	if err := initSTH(tt); err != nil {
		return nil, fmt.Errorf("initalizing STH: %w", err)
	}

	return tt, nil
}

// initSTH initializes a tree with an empty tree STH.
func initSTH(tt *testTree) error {
	emptyRootHash := sha256.Sum256(nil)

	// init the new tree by signing a STH for the empty root
	slr := types.LogRoot{
		Version: tls.Enum(trillian.LogRootFormat_LOG_ROOT_FORMAT_V1),
		V1: &types.LogRootV1{
			TreeSize:       0,
			RootHash:       emptyRootHash[:],
			TimestampNanos: uint64(timeSource.Now().UnixNano()),
		},
	}
	slrBytes, err := tls.Marshal(slr)
	if err != nil {
		return err
	}

	// store the new STH
	err = tt.logStorage.ReadWriteTransaction(context.Background(), tt.tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		return tx.StoreSignedLogRoot(ctx, &trillian.SignedLogRoot{
			LogRoot: slrBytes,
		})
	})
	if err != nil {
		return fmt.Errorf("storing STH: %w", err)
	}

	return nil
}

// newLog creates a new testLog with the given private key and optional window
// start/end times.
func newLog(key *ecdsa.PrivateKey, windowStart, windowEnd *time.Time) (*testLog, error) {
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

		windowStart: windowStart,
		windowEnd:   windowEnd,
	}, nil
}

// switchTrees toggles the active tree between treeA and treeB.
// It returns the new active tree.
func (tl *testLog) switchTrees() *testTree {
	if tl.activeTree == tl.treeA {
		tl.activeTree = tl.treeB
	} else {
		tl.activeTree = tl.treeA
	}
	return tl.activeTree
}

// getProof gets a trillian consistency proof between the first and second tree
// sizes, or returns an error. Minimal request parameter validation is done.
func (tl *testLog) getProof(first, second int64) (*trillian.GetConsistencyProofResponse, error) {
	tx, err := tl.activeTree.logStorage.SnapshotForTree(context.Background(), tl.activeTree.tree)
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

	nodeFetches, err := merkle.CalcConsistencyProofNodeAddresses(first, second)
	if err != nil {
		return nil, err
	}

	proof, err := fetchNodesAndBuildProof(context.Background(), tx, tl.activeTree.hasher, 0, nodeFetches)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(context.Background()); err != nil {
		return nil, err
	}

	resp := &trillian.GetConsistencyProofResponse{
		SignedLogRoot: slr,
		Proof:         proof,
	}
	return resp, nil
}

// getSTH returns the signed tree head for the currently active testlog tree.
func (tl *testLog) getSTH() (*ct.SignedTreeHead, error) {
	tx, err := tl.activeTree.logStorage.SnapshotForTree(context.Background(), tl.activeTree.tree)
	defer func() { _ = tx.Close() }()

	if err != nil {
		return nil, err
	}

	signedLogRoot, err := tx.LatestSignedLogRoot(context.Background())
	if err != nil {
		return nil, err
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return nil, err
	}

	var slr ct.SignedTreeHead
	_, err = tls.Unmarshal(signedLogRoot.LogRoot, &slr)
	if err != nil {
		return nil, err
	}

	sth := ct.SignedTreeHead{
		Version:   ct.V1,
		TreeSize:  slr.TreeSize,
		Timestamp: slr.Timestamp,
	}
	copy(sth.SHA256RootHash[:], slr.SHA256RootHash[:])

	sthBytes := signedLogRoot.LogRoot
	hash := sha256.Sum256(sthBytes)
	signature, err := tl.key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(tl.key.Public()),
		},
		Signature: signature,
	}
	return &sth, nil
}

// addChain queues a chain of ct.ASN1Certs (or precerts) to the currently active
// testLog tree and returns a SCT for the submission or an error.
func (tl *testLog) addChain(chain []ct.ASN1Cert, precert bool) (*ct.SignedCertificateTimestamp, error) {
	entryType := ct.X509LogEntryType
	if precert {
		entryType = ct.PrecertLogEntryType
	}

	cert, err := x509.ParseCertificate(chain[0].Data)
	if err != nil {
		return nil, err
	}
	if tl.windowStart != nil {
		if cert.NotBefore.Before(*tl.windowStart) {
			return nil, fmt.Errorf(
				"cert not before %q is outside log window start %q",
				cert.NotBefore, *tl.windowStart)
		}
	}
	if tl.windowEnd != nil {
		if cert.NotAfter.After(*tl.windowEnd) {
			return nil, fmt.Errorf(
				"cert not after %q is outside log window end %q",
				cert.NotAfter, *tl.windowEnd)
		}
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

	logLeaf.MerkleLeafHash = tl.activeTree.hasher.HashLeaf(logLeaf.LeafValue)
	logLeaf.LeafIdentityHash = logLeaf.MerkleLeafHash

	leaves := []*trillian.LogLeaf{&logLeaf}
	queuedLeaves, err := tl.activeTree.logStorage.QueueLeaves(context.Background(), tl.activeTree.tree, leaves, now)
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
	signature, err := tl.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	ds := ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(tl.key.Public()),
		},
		Signature: signature,
	}

	logID, err := ctfe.GetCTLogID(tl.key.Public())
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
func (tl *testLog) integrateBatch(count int64) (int, error) {
	integratedCount, err := log.IntegrateBatch(
		context.Background(),
		tl.activeTree.tree,
		int(count),
		time.Duration(0),
		0,
		timeSource,
		tl.activeTree.logStorage,
		nil)
	if err != nil {
		return 0, err
	}
	return integratedCount, nil
}

// signSTH uses the testlog's private key to sign a STH provided externally for
// use as a mock response.
func (tl *testLog) signSTH(sth *ct.SignedTreeHead) error {
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(sthBytes)
	signature, err := tl.key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(tl.key.Public()),
		},
		Signature: signature,
	}

	return nil
}

// getEntries returns a slice of trillian.LogLeaf pointers between the provided
// start and end point of the tree.
func (tl *testLog) getEntries(start, end int64) ([]*trillian.LogLeaf, error) {
	tx, err := tl.activeTree.logStorage.SnapshotForTree(context.Background(), tl.activeTree.tree)
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
		return nil, fmt.Errorf("start index %d is larger than tree size %d", start, root.TreeSize)
	}

	return tx.GetLeavesByRange(context.Background(), start, end-start)
}
