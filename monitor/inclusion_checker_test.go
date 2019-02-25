package monitor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jmhodges/clock"
	dto "github.com/prometheus/client_model/go"

	"github.com/letsencrypt/ct-woodpecker/storage"
)

type malleableClient struct {
	GetSTHFunc     func(context.Context) (*ct.SignedTreeHead, error)
	GetEntriesFunc func(context.Context, int64, int64) ([]ct.LogEntry, error)
}

func (c malleableClient) GetSTH(ctx context.Context) (*ct.SignedTreeHead, error) {
	return c.GetSTHFunc(ctx)
}

func (c malleableClient) GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error) {
	return c.GetEntriesFunc(ctx, start, end)
}

func TestGetEntries(t *testing.T) {
	mc := malleableClient{
		GetEntriesFunc: func(_ context.Context, _, _ int64) ([]ct.LogEntry, error) { return nil, errors.New("nop") },
	}
	mdb := &storage.MalleableTestDB{}
	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, nil
	}
	ic, err := newInclusionChecker(
		monitorCheck{
			logURI: "test-log",
			logID:  1,
			label:  "inclusionChecker",
			clk:    clock.NewFake(),
			stdout: log.New(os.Stdout, "", log.LstdFlags),
			stderr: log.New(os.Stdout, "", log.LstdFlags),
		},
		&InclusionOptions{
			FetchBatchSize: 0,
		},
		mc,
		logKey,
		mdb)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	_, _, err = ic.getEntries(0, 1)
	if err == nil {
		t.Fatal("Expected error when GetEntries failed")
	}

	// return three entries, one at a time (because batchSize is 0)
	mc.GetEntriesFunc = func(_ context.Context, start, end int64) ([]ct.LogEntry, error) {
		entries := []ct.LogEntry{{}, {}, {}}
		return entries[start : end+1], nil
	}
	ic.client = mc
	newHead, entries, err := ic.getEntries(0, 3)
	if err != nil {
		t.Fatalf("Expected no error: %s", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Unexpected number of entries returned, expected: 3, got: %d", len(entries))
	}
	if newHead != 3 {
		t.Fatalf("Unexpected newHead, expected: 3, got: %d", newHead)
	}

	// return three entries, one at a time (but batchSize is 1, so expecting 2 per call)
	ic.batchSize = 1
	mc.GetEntriesFunc = func(_ context.Context, start, end int64) ([]ct.LogEntry, error) {
		entries := []ct.LogEntry{{}, {}, {}}
		return []ct.LogEntry{entries[start]}, nil
	}
	ic.client = mc
	newHead, entries, err = ic.getEntries(0, 3)
	if err != nil {
		t.Fatalf("Expected no error: %s", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Unexpected number of entries returned, expected: 3, got: %d", len(entries))
	}
	if newHead != 3 {
		t.Fatalf("Unexpected newHead, expected: 3, got: %d", newHead)
	}
}

func TestCheckEntries(t *testing.T) {
	fc := clock.NewFake()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	keyString := base64.StdEncoding.EncodeToString(pubKeyBytes)
	mdb := &storage.MalleableTestDB{}
	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, nil
	}
	ic, err := newInclusionChecker(
		monitorCheck{
			logURI: "test-log",
			logID:  1,
			label:  "inclusionChecker",
			clk:    fc,
			stdout: log.New(os.Stdout, "", log.LstdFlags),
			stderr: log.New(os.Stdout, "", log.LstdFlags),
		},
		&InclusionOptions{},
		nil,
		keyString,
		mdb)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// No matching certs
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2}},
	}, []ct.LogEntry{
		{
			X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
			Leaf:     ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{EntryType: ct.X509LogEntryType}},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// Matching cert, invalid SCT
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: []byte{255, 255, 255}},
	}, []ct.LogEntry{
		{
			X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
			Leaf:     ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{EntryType: ct.X509LogEntryType}},
		},
	})
	if err == nil {
		t.Fatal("Expected error for invalid SCT")
	}

	// Matching cert, wrong SCT
	sct, _ := cttls.Marshal(ct.SignedCertificateTimestamp{Timestamp: 1234})
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct, Timestamp: 123},
	}, []ct.LogEntry{
		{
			X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
			Leaf:     ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{EntryType: ct.X509LogEntryType}},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// Matching cert, SCT with invalid signature
	sct, _ = cttls.Marshal(ct.SignedCertificateTimestamp{Timestamp: 1234})
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct, Timestamp: 1234},
	}, []ct.LogEntry{
		{
			X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
			Leaf: ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{
				EntryType: ct.X509LogEntryType,
				Timestamp: 1234,
			}},
		},
	})
	if err == nil {
		t.Fatal("Expected error for invalid SCT signature")
	}

	// Matching cert, correct SCT, DB failure
	sctObj := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  1234,
	}
	data, _ := ct.SerializeSCTSignatureInput(sctObj, ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: 1234,
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: []byte{1, 2, 3}},
		},
	}})
	h := sha256.Sum256(data)
	signature, _ := k.Sign(rand.Reader, h[:], crypto.SHA256)
	digitallySigned := ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(k.Public()),
		},
		Signature: signature,
	}
	sct, _ = cttls.Marshal(ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  1234,
		Signature:  digitallySigned,
	})
	mdb.MarkCertSeenFunc = func(_ int, _ time.Time) error {
		return errors.New("nop")
	}
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct, Timestamp: 1234},
	}, []ct.LogEntry{
		{
			X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
			Leaf: ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{
				EntryType: ct.X509LogEntryType,
				Timestamp: 1234,
				X509Entry: &ct.ASN1Cert{Data: []byte{1, 2, 3}},
			}},
		},
	})
	if err == nil {
		t.Fatal("Expected error for MarkCertSeen failure")
	}

	// Matching cert, correct SCT, DB storage works
	mdb.MarkCertSeenFunc = func(_ int, _ time.Time) error {
		return nil
	}
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct},
	}, []ct.LogEntry{
		{
			X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
			Leaf: ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{
				EntryType: ct.X509LogEntryType,
				Timestamp: 1234,
				X509Entry: &ct.ASN1Cert{Data: []byte{1, 2, 3}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// Redo above but with a precert
	data, _ = ct.SerializeSCTSignatureInput(sctObj, ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: 1234,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  [32]byte{},
				TBSCertificate: []byte{1, 2, 3},
			},
		},
	}})
	h = sha256.Sum256(data)
	signature, _ = k.Sign(rand.Reader, h[:], crypto.SHA256)
	digitallySigned = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(k.Public()),
		},
		Signature: signature,
	}
	sct, _ = cttls.Marshal(ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  1234,
		Signature:  digitallySigned,
	})
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct, Timestamp: 1234},
	}, []ct.LogEntry{
		{
			Precert: &ct.Precertificate{
				IssuerKeyHash:  [32]byte{},
				TBSCertificate: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
				Submitted:      ct.ASN1Cert{Data: []byte{1, 2, 3}},
			},
			Leaf: ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{
				EntryType: ct.PrecertLogEntryType,
				Timestamp: 1234,
				PrecertEntry: &ct.PreCert{
					IssuerKeyHash:  [32]byte{},
					TBSCertificate: []byte{1, 2, 3},
				},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// Check oldest_unincorporated_cert is properly set
	oldestUnseen.WithLabelValues("test-log").Set(0)
	fc.Add(time.Hour)
	_, _, err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct, Timestamp: 1234},
		{Cert: []byte{1, 2, 3, 4}, SCT: sct, Timestamp: 1234},
	}, []ct.LogEntry{})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	var metric dto.Metric
	_ = oldestUnseen.WithLabelValues("test-log").Write(&metric)
	if metric.Gauge.GetValue() != 3599 {
		t.Fatalf("Unexpected oldest_unincorporated_cert value, expected: 9223372036.854776, got: %f", *metric.Gauge.Value)
	}
}

func TestCheckInclusion(t *testing.T) {
	fc := clock.NewFake()
	mdb := &storage.MalleableTestDB{}
	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, nil
	}
	mc := &malleableClient{}
	ic, err := newInclusionChecker(
		monitorCheck{
			logURI: "test-log",
			logID:  1,
			label:  "inclusionChecker",
			clk:    fc,
			stdout: log.New(os.Stdout, "", log.LstdFlags),
			stderr: log.New(os.Stdout, "", log.LstdFlags),
		},
		&InclusionOptions{
			FetchBatchSize: 1000,
		},
		mc,
		logKey,
		mdb)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when db.GetIndex failed")
	}

	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, nil
	}
	//nolint:unparam
	mdb.GetUnseenFunc = func(int64) ([]storage.SubmittedCert, error) {
		return nil, errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when db.GetUnseen failed")
	}

	//nolint:unparam
	mdb.GetUnseenFunc = func(int64) ([]storage.SubmittedCert, error) {
		return []storage.SubmittedCert{}, nil
	}
	err = ic.checkInclusion()
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	//nolint:unparam
	mdb.GetUnseenFunc = func(int64) ([]storage.SubmittedCert, error) {
		return []storage.SubmittedCert{
			{
				Cert: []byte{0, 1, 2},
			},
		}, nil
	}
	mc.GetSTHFunc = func(context.Context) (*ct.SignedTreeHead, error) {
		return nil, errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when client.GetSTH failed")
	}

	mc.GetSTHFunc = func(context.Context) (*ct.SignedTreeHead, error) {
		return &ct.SignedTreeHead{TreeSize: 2}, nil
	}
	mc.GetEntriesFunc = func(_ context.Context, start, end int64) ([]ct.LogEntry, error) {
		return nil, errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when getEntries failed")
	}

	// Provide a picky GetEntriesFunc that rejects `end` if it's too big. Test for
	// an off-by-one error we used to have.
	treeSize := 2
	mdb.UpdateIndexFunc = func(int64, int64) error {
		return nil
	}
	mc.GetSTHFunc = func(context.Context) (*ct.SignedTreeHead, error) {
		return &ct.SignedTreeHead{TreeSize: uint64(treeSize)}, nil
	}
	mc.GetEntriesFunc = func(_ context.Context, start, end int64) ([]ct.LogEntry, error) {
		if end >= int64(treeSize) {
			return nil, fmt.Errorf("end of range is greater than or equal to tree size. Got end=%d", end)
		}
		tree := []ct.LogEntry{
			{
				Precert: &ct.Precertificate{
					IssuerKeyHash:  [32]byte{},
					TBSCertificate: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
					Submitted:      ct.ASN1Cert{Data: []byte{1, 2, 3}},
				},
				Leaf: ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{
					EntryType: ct.PrecertLogEntryType,
					Timestamp: 1234,
					PrecertEntry: &ct.PreCert{
						IssuerKeyHash:  [32]byte{},
						TBSCertificate: []byte{1, 2, 3},
					},
				}},
			},
			{
				Precert: &ct.Precertificate{
					IssuerKeyHash:  [32]byte{},
					TBSCertificate: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
					Submitted:      ct.ASN1Cert{Data: []byte{1, 2, 3}},
				},
				Leaf: ct.MerkleTreeLeaf{TimestampedEntry: &ct.TimestampedEntry{
					EntryType: ct.PrecertLogEntryType,
					Timestamp: 1234,
					PrecertEntry: &ct.PreCert{
						IssuerKeyHash:  [32]byte{},
						TBSCertificate: []byte{1, 2, 3},
					},
				}},
			},
		}
		return tree[start : end+1], nil
	}
	err = ic.checkInclusion()
	if err != nil {
		t.Fatalf("Expected checkInclusion to call GetEntries with end smaller than tree size. Got %s", err)
	}

	mc.GetEntriesFunc = func(context.Context, int64, int64) ([]ct.LogEntry, error) {
		return []ct.LogEntry{
			{
				X509Cert: &ctx509.Certificate{Raw: []byte{0, 1, 2}},
				Leaf: ct.MerkleTreeLeaf{
					TimestampedEntry: &ct.TimestampedEntry{
						EntryType: ct.X509LogEntryType,
					},
				},
			},
		}, nil
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when getEntries failed")
	}

	mc.GetEntriesFunc = func(context.Context, int64, int64) ([]ct.LogEntry, error) {
		return []ct.LogEntry{
			{
				X509Cert: &ctx509.Certificate{Raw: []byte{1, 2, 3}},
				Leaf: ct.MerkleTreeLeaf{
					TimestampedEntry: &ct.TimestampedEntry{
						EntryType: ct.X509LogEntryType,
					},
				},
			},
		}, nil
	}
	mdb.UpdateIndexFunc = func(int64, int64) error {
		return errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when db.updateIndex failed")
	}

	mdb.UpdateIndexFunc = func(int64, int64) error {
		return nil
	}
	err = ic.checkInclusion()
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}
