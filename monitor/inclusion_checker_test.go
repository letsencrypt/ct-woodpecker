package monitor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
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
	ic := inclusionChecker{client: &mc, batchSize: 0}

	_, _, err := ic.getEntries(0, 1)
	if err == nil {
		t.Fatal("Expected error when GetEntries failed")
	}

	// return three entries, one at a time (because batchSize is 0)
	mc.GetEntriesFunc = func(_ context.Context, start, end int64) ([]ct.LogEntry, error) {
		entries := []ct.LogEntry{{}, {}, {}}
		return entries[start : end+1], nil
	}
	newHead, entries, err := ic.getEntries(0, 2)
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
	newHead, entries, err = ic.getEntries(0, 2)
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

type malleableDB struct {
	AddCertFunc      func(int64, *storage.SubmittedCert) error
	GetUnseenFunc    func(int64) ([]storage.SubmittedCert, error)
	MarkCertSeenFunc func(int, time.Time) error
	GetIndexFunc     func(int64) (int64, error)
	UpdateIndexFunc  func(int64, int64) error
}

func (s *malleableDB) AddCert(logID int64, cert *storage.SubmittedCert) error {
	return s.AddCertFunc(logID, cert)
}

func (s *malleableDB) GetUnseen(logID int64) ([]storage.SubmittedCert, error) {
	return s.GetUnseenFunc(logID)
}

func (s *malleableDB) MarkCertSeen(id int, seen time.Time) error {
	return s.MarkCertSeenFunc(id, seen)
}

func (s *malleableDB) GetIndex(logID int64) (int64, error) {
	return s.GetIndexFunc(logID)
}

func (s *malleableDB) UpdateIndex(logID int64, index int64) error {
	return s.UpdateIndexFunc(logID, index)
}

func TestCheckEntries(t *testing.T) {
	fc := clock.NewFake()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sv, _ := ct.NewSignatureVerifier(k.Public())
	mdb := &malleableDB{}
	ic := inclusionChecker{
		logger:           log.New(os.Stdout, "", log.LstdFlags),
		clk:              fc,
		db:               mdb,
		signatureChecker: sv,
	}

	// No matching certs
	err := ic.checkEntries([]storage.SubmittedCert{
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
	err = ic.checkEntries([]storage.SubmittedCert{
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
	err = ic.checkEntries([]storage.SubmittedCert{
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
	err = ic.checkEntries([]storage.SubmittedCert{
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
	err = ic.checkEntries([]storage.SubmittedCert{
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
	err = ic.checkEntries([]storage.SubmittedCert{
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
	err = ic.checkEntries([]storage.SubmittedCert{
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
	oldestUnseen.Set(0)
	fc.Add(time.Hour)
	err = ic.checkEntries([]storage.SubmittedCert{
		{Cert: []byte{1, 2, 3}, SCT: sct, Timestamp: 1234},
		{Cert: []byte{1, 2, 3, 4}, SCT: sct, Timestamp: 1234},
	}, []ct.LogEntry{})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	var metric dto.Metric
	_ = oldestUnseen.Write(&metric)
	if metric.Gauge.GetValue() != 3599 {
		t.Fatalf("Unexpected oldest_unincorporated_cert value, expected: 9223372036.854776, got: %f", *metric.Gauge.Value)
	}
}

func TestCheckInclusion(t *testing.T) {
	fc := clock.NewFake()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sv, _ := ct.NewSignatureVerifier(k.Public())
	mdb := &malleableDB{}
	mc := &malleableClient{}
	ic := inclusionChecker{
		logger:           log.New(os.Stdout, "", log.LstdFlags),
		clk:              fc,
		db:               mdb,
		client:           mc,
		signatureChecker: sv,
	}

	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, errors.New("bad")
	}
	err := ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when db.GetIndex failed")
	}

	mdb.GetIndexFunc = func(int64) (int64, error) {
		return 0, nil
	}
	mdb.GetUnseenFunc = func(int64) ([]storage.SubmittedCert, error) {
		return nil, errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when db.GetUnseen failed")
	}

	mdb.GetUnseenFunc = func(int64) ([]storage.SubmittedCert, error) {
		return []storage.SubmittedCert{}, nil
	}
	err = ic.checkInclusion()
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

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
		return &ct.SignedTreeHead{TreeSize: 1}, nil
	}
	mc.GetEntriesFunc = func(context.Context, int64, int64) ([]ct.LogEntry, error) {
		return nil, errors.New("bad")
	}
	err = ic.checkInclusion()
	if err == nil {
		t.Fatal("Expected checkInclusion to fail when getEntries failed")
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
