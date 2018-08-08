package monitor

import (
	"context"
	"errors"
	"log"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/pki"
)

const (
	logKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElgyN7ptarCAX5krBwDwjhHM+b0xJjCKke+Dfr3GWSbLm3eO7muXRo8FDDdpdiRpnG4NJT0bdzq5YEer4C2eZ+g=="
)

func TestNew(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())

	logURI := "test"
	fetchDuration := time.Second
	certInterval := time.Second

	// Creating a monitor with an illegal key should fail
	_, err := New(
		MonitorOptions{
			LogURI: logURI,
			LogKey: "⚷",
		}, l, l, clk)
	if err == nil {
		t.Errorf("Expected New() with invalid key to error")
	}

	// Creating a monitor with vaild configuration should not fail
	m, err := New(
		MonitorOptions{
			LogURI: logURI,
			LogKey: logKey,
			FetchOpts: &FetcherOptions{
				Interval: fetchDuration,
				Timeout:  time.Second,
			},
		}, l, l, clk)
	if err != nil {
		t.Fatalf("Expected no error calling New(), got %s", err.Error())
	}
	if m == nil {
		t.Fatalf("Expected a non-nil monitor from New() when err == nil")
	}

	if m.stdout != l {
		t.Errorf("Expected monitor stdout logger to be set to %p, got %p", l, m.stdout)
	}
	if m.stderr != l {
		t.Errorf("Expected monitor stderr logger to be set to %p, got %p", l, m.stdout)
	}

	if m.fetcher == nil {
		t.Fatalf("Expected monitor to have a non-nil fetcher")
	}

	if m.fetcher.logURI != logURI {
		t.Errorf("Expected monitor fetcher logURI to be %q, got %q", logURI, m.fetcher.logURI)
	}

	if m.fetcher.sthFetchInterval != fetchDuration {
		t.Errorf("Expected monitor fetcher sthFetchDuration %s got %s", m.fetcher.sthFetchInterval, fetchDuration)
	}

	if m.fetcher.stats == nil {
		t.Error("Expected monitor fetcher stats to be non-nil")
	}

	if m.fetcher.client == nil {
		t.Errorf("Expected monitor fetcher client to be non-nil")
	}

	// With no SubmitOpts there should be no submitter
	if m.submitter != nil {
		t.Fatalf("Expected monitor to have a nil submitter")
	}

	cert, err := pki.LoadCertificate("../test/issuer.pem")
	if err != nil {
		t.Fatalf("Unable to load ../test/issuer.pem cert: %s\n", err.Error())
	}

	key, err := pki.LoadPrivateKey("../test/issuer.key")
	if err != nil {
		t.Fatalf("Unable to load ../test/issuer.pem cert: %s\n", err.Error())
	}

	// Creating a monitor with a issuer key and cert should not error
	m, err = New(
		MonitorOptions{
			LogURI: logURI,
			LogKey: logKey,
			SubmitOpts: &SubmitterOptions{
				Timeout:       time.Second,
				Interval:      fetchDuration,
				IssuerKey:     key,
				IssuerCert:    cert,
				SubmitPreCert: true,
			},
		}, l, l, clk)
	if err != nil {
		t.Fatalf("Unexpected error creating monitor with submitter: %s", err)
	}

	if m.fetcher != nil {
		t.Errorf("Expected monitor to have a nil fetcher")
	}

	if m.submitter == nil {
		t.Fatalf("Expected monitor to have a non-nil submitter")
	}

	if m.submitter.certSubmitInterval != certInterval {
		t.Errorf("Expected monitor submitter certSubmitInterval %s got %s", m.submitter.certSubmitInterval, certInterval)
	}

	if !m.submitter.submitPreCert {
		t.Errorf("Expected monitor submitter to have true submitPreCert, was false")
	}

	if m.submitter.stats == nil {
		t.Error("Expected monitor submitter stats to be non-nil")
	}

	if m.submitter.client == nil {
		t.Errorf("Expected monitor submitter client to be non-nil")
	}
}

// errorClient is a type implementing the monitorCTClient interface with
// `GetSTH` and `AddChain` functions that always returns an error.
type errorClient struct{}

// GetSTH mocked to always return an error
func (c errorClient) GetSTH(_ context.Context) (*ct.SignedTreeHead, error) {
	return nil, errors.New("ct-log logged off")
}

// AddChain mocked to always return an error
func (c errorClient) AddChain(_ context.Context, _ []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, errors.New("ct-log doesn't want any chains")
}

// AddPreChain mocked to always return an error
func (c errorClient) AddPreChain(_ context.Context, _ []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, errors.New("ct-log doesn't want any prechains")
}

func (c errorClient) GetEntries(_ context.Context, _, _ int64) ([]ct.LogEntry, error) {
	return nil, errors.New("ct-log has no entries")
}

// GetSTHConsistency mocked to always return an error
func (c errorClient) GetSTHConsistency(_ context.Context, _ uint64, _ uint64) ([][]byte, error) {
	return nil, errors.New("ct-log wants you to take its word that it is consistent")
}

// mockClient is a type implementing the monitorCTClient interface that always
// returns a mock STH from `GetSTH`, a mock SCT from `AddChain`, and a mock
// proof from `GetSTHConsistency`
type mockClient struct {
	timestamp time.Time
	proof     [][]byte
}

// GetSTH mocked to always return a fixed mock STH
func (c mockClient) GetSTH(_ context.Context) (*ct.SignedTreeHead, error) {
	ts := c.timestamp.UnixNano() / int64(time.Millisecond)
	return &ct.SignedTreeHead{
		Timestamp: uint64(ts),
	}, nil
}

// AddChain mocked to always return a fixed mock SCT
func (c mockClient) AddChain(_ context.Context, _ []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	ts := c.timestamp.UnixNano() / int64(time.Millisecond)
	return &ct.SignedCertificateTimestamp{
		Timestamp: uint64(ts),
	}, nil
}

// AddPreChain mocked to always return a fixed mock SCT
func (c mockClient) AddPreChain(_ context.Context, _ []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	ts := c.timestamp.UnixNano() / int64(time.Millisecond)
	return &ct.SignedCertificateTimestamp{
		Timestamp: uint64(ts),
	}, nil
}

func (c mockClient) GetEntries(_ context.Context, _, _ int64) ([]ct.LogEntry, error) {
	return []ct.LogEntry{}, nil
}

// GetSTHConsistency mocked to always return a fixed consistency proof
func (c mockClient) GetSTHConsistency(_ context.Context, _ uint64, _ uint64) ([][]byte, error) {
	return c.proof, nil
}
