package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"log"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/letsencrypt/ct-woodpecker/storage"
	"github.com/letsencrypt/ct-woodpecker/test"
	"github.com/prometheus/client_golang/prometheus"
)

func assertLatencySamples(t *testing.T, logURI string, precert bool, expected int, histogram *prometheus.HistogramVec) {
	labels := prometheus.Labels{"uri": logURI, "precert": strconv.FormatBool(precert)}
	latencyObservations := test.CountHistogramSamplesWithLabels(histogram, labels)
	if latencyObservations != expected {
		t.Errorf("Expected %d latency histogram samples. Found %d",
			expected, latencyObservations)
	}
}

func assertCounterVecCount(t *testing.T, labels prometheus.Labels, expected int, counter *prometheus.CounterVec) {
	count := test.CountCounterVecWithLabels(counter, labels)
	if count != expected {
		t.Errorf("Expected countervec to be %d, was %d", expected, count)
	}
}

func TestSubmitCertificate(t *testing.T) {
	clk := clock.NewFake()
	clk.Set(time.Now())
	certInterval := time.Second
	certTimeout := time.Millisecond * 5
	logURI := "test"

	// Create a logger backed by the safeBuffer. The log.Logger type is only safe
	// for concurrent use when the backing buffer is. Using a raw bytes.Buffer
	// with a shared logger will cause data races.
	var out test.SafeBuffer
	l := log.New(&out, "TestSubmitCertificate ", log.LstdFlags)

	certIssuer, err := pki.LoadCertificate("../test/issuer.pem")
	if err != nil {
		t.Fatalf("Error loading issuer cert: %s", err.Error())
	}
	certIssuerKey, err := pki.LoadPrivateKey("../test/issuer.key")
	if err != nil {
		t.Fatalf("Error loading issuer key: %s", err.Error())
	}

	// Create a monitor configured with an certIssuer and certIssuerKey that is
	// configured to submit precerts
	m, err := New(
		MonitorOptions{
			LogURI: logURI,
			LogKey: logKey,
			SubmitOpts: &SubmitterOptions{
				Interval:      certInterval,
				Timeout:       certTimeout,
				IssuerKey:     certIssuerKey,
				IssuerCert:    certIssuer,
				SubmitCert:    true,
				SubmitPreCert: true,
			},
		}, l, l, clk)
	if err != nil {
		t.Fatalf("Unexpected error from New(): %s", err.Error())
	}

	sctWindow := requiredSCTFreshness + time.Second
	tooOld := clk.Now().Add(-sctWindow)
	tooNew := clk.Now().Add(sctWindow)
	justRight := clk.Now().Add(sctWindow / 2)

	testCases := []struct {
		Name          string
		MockClient    monitorCTClient
		ExpectSuccess bool
	}{
		{
			Name:       "Submission failure",
			MockClient: errorClient{},
		},
		{
			Name:       "SCT too old",
			MockClient: mockClient{timestamp: tooOld},
		},
		{
			Name:       "SCT too new",
			MockClient: mockClient{timestamp: tooNew},
		},
		{
			Name:          "SCT just right",
			MockClient:    mockClient{timestamp: justRight},
			ExpectSuccess: true,
		},
	}

	successCount := 0
	failCount := 0

	for i, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			m.submitter.client = tc.MockClient
			m.submitter.submitCertificates()

			// Sleep for the submission timeout to allow the async submissions to
			// complete
			time.Sleep(certTimeout)

			// There should be 1 latency observation for each test case
			expectedLatencyObservations := i + 1
			// Check once for precerts
			assertLatencySamples(t, logURI, true, expectedLatencyObservations, m.submitter.stats.certSubmitLatency)
			// and again for full certs
			assertLatencySamples(t, logURI, false, expectedLatencyObservations, m.submitter.stats.certSubmitLatency)

			// Increment one of the expected metrics based on whether the cert
			// submission was expected to pass or fail
			if tc.ExpectSuccess {
				successCount++
			} else {
				failCount++
			}

			// There should be the correct number of failed precert submissions
			assertCounterVecCount(t, prometheus.Labels{"uri": logURI, "status": "fail", "precert": "true", "duplicate": "false"}, failCount, m.submitter.stats.certSubmitResults)
			// and the correct number of failed cert submissions
			assertCounterVecCount(t, prometheus.Labels{"uri": logURI, "status": "fail", "precert": "false", "duplicate": "false"}, failCount, m.submitter.stats.certSubmitResults)

			// There should also be the correct number of successful precert submissions
			assertCounterVecCount(t, prometheus.Labels{"uri": logURI, "status": "ok", "precert": "true", "duplicate": "false"}, successCount, m.submitter.stats.certSubmitResults)
			// and the correct number of successful cert submissions
			assertCounterVecCount(t, prometheus.Labels{"uri": logURI, "status": "ok", "precert": "false", "duplicate": "false"}, successCount, m.submitter.stats.certSubmitResults)
		})
	}
}

type dupeClient struct {
	sct *ct.SignedCertificateTimestamp
}

func (dc *dupeClient) GetSTH(_ context.Context) (*ct.SignedTreeHead, error) {
	return &ct.SignedTreeHead{}, nil
}

func (dc *dupeClient) AddChain(_ context.Context, _ []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return dc.sct, nil
}

func (dc *dupeClient) AddPreChain(_ context.Context, _ []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return dc.sct, nil
}

func (dc *dupeClient) GetEntries(_ context.Context, _, _ int64) ([]ct.LogEntry, error) {
	return []ct.LogEntry{}, nil
}

func (dc *dupeClient) GetSTHConsistency(_ context.Context, _ uint64, _ uint64) ([][]byte, error) {
	return [][]byte{}, nil
}

func TestSubmitIncludedDupe(t *testing.T) {
	mdb := &storage.MalleableTestDB{}
	dc := dupeClient{}
	c := newCertSubmitter(
		monitorCheck{
			logURI: "test-log",
			logID:  1,
			label:  "certSubmitter",
			clk:    clock.New(),
			stdout: log.New(os.Stdout, "", log.LstdFlags),
			stderr: log.New(os.Stdout, "", log.LstdFlags),
		},
		&SubmitterOptions{
			IssuerCert: &x509.Certificate{Raw: []byte{1, 2, 3}},
		},
		&dc,
		mdb)

	testCases := []struct {
		setup       func()
		submissions int
		newSCTs     int
	}{
		{
			setup: func() {
				// No included certificates to return
				mdb.GetRandSeenFunc = func(logID int64) (*storage.SubmittedCert, error) {
					return nil, sql.ErrNoRows
				}
			},
			submissions: 0,
			newSCTs:     0,
		},
		{
			setup: func() {
				// Same SCT returned
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					panic(err)
				}
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(10),
				}
				cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
				if err != nil {
					panic(err)
				}
				mdb.GetRandSeenFunc = func(logID int64) (*storage.SubmittedCert, error) {
					return &storage.SubmittedCert{
						ID:        1,
						Cert:      cert,
						SCT:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						Timestamp: 1,
					}, nil
				}
				dc.sct = &ct.SignedCertificateTimestamp{}
			},
			submissions: 1,
			newSCTs:     0,
		},
		{
			setup: func() {
				// Different SCT returned
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					panic(err)
				}
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(10),
				}
				cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
				if err != nil {
					panic(err)
				}
				mdb.GetRandSeenFunc = func(logID int64) (*storage.SubmittedCert, error) {
					return &storage.SubmittedCert{
						ID:        1,
						Cert:      cert,
						SCT:       []byte{0},
						Timestamp: 1,
					}, nil
				}
				mdb.AddCertFunc = func(int64, *storage.SubmittedCert) error {
					return nil
				}
				dc.sct = &ct.SignedCertificateTimestamp{}
			},
			submissions: 1,
			newSCTs:     1,
		},
	}

	prevSubmissions := 0
	prevSCTs := 0
	for _, tc := range testCases {
		tc.setup()

		err := c.submitIncludedDupe()
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}

		assertCounterVecCount(t, prometheus.Labels{"uri": c.logURI, "status": "ok", "precert": "false", "duplicate": "true"}, tc.submissions+prevSubmissions, c.stats.certSubmitResults)
		newSCTsCount := test.CountCounter(c.stats.storedSCTs)
		if newSCTsCount != tc.newSCTs+prevSCTs {
			t.Fatalf("Expected %d new SCTs, got %d", tc.newSCTs, newSCTsCount-prevSCTs)
		}
		prevSubmissions += tc.submissions
		prevSCTs += tc.newSCTs
	}
}
