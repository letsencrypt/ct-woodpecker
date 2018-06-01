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
	"github.com/letsencrypt/ct-woodpecker/test"
	"github.com/prometheus/client_golang/prometheus"
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
	_, err := New(logURI, "⚷", fetchDuration, certInterval, nil, nil, l, clk)
	if err == nil {
		t.Errorf("Expected New() with invalid key to error")
	}

	// Creating a monitor with vaild configuration should not fail
	m, err := New(logURI, logKey, fetchDuration, certInterval, nil, nil, l, clk)
	if err != nil {
		t.Fatalf("Expected no error calling New(), got %s", err.Error())
	}
	if m == nil {
		t.Fatalf("Expected a non-nil monitor from New() when err == nil")
	}

	if m.logger != l {
		t.Errorf("Expected monitor logger to be set to %p, got %p", l, m.logger)
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

	// With no issuer key there should be no submitter
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
	m, err = New(logURI, logKey, fetchDuration, certInterval, key, cert, l, clk)
	if err != nil {
		t.Fatalf("Unexpected error creating monitor with submitter")
	}

	if m.submitter == nil {
		t.Fatalf("Expected monitor to have a non-nil submitter")
	}

	if m.submitter.certSubmitInterval != certInterval {
		t.Errorf("Expected monitor submitter certSubmitInterval %s got %s", m.submitter.certSubmitInterval, certInterval)
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

// mockClient is a type implementing the monitorCTClient interface that always
// returns a fixed mock STH from `GetSTH` and a mock SCT from `AddChain`
type mockClient struct {
	timestamp time.Time
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

func TestObserveSTH(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchDuration := time.Second
	certInterval := time.Second
	logURI := "test"
	labels := prometheus.Labels{"uri": logURI}

	m, err := New(logURI, logKey, fetchDuration, certInterval, nil, nil, l, clk)
	if err != nil {
		t.Fatalf("Unexpected error from New(): %s", err.Error())
	}

	// Replace the monitor's fetcher's client with one that always fails
	m.fetcher.client = errorClient{}
	// Make an STH observation
	m.fetcher.observeSTH()

	// Failures should have a latency observation
	latencyObservations, err := test.CountHistogramSamplesWithLabels(m.fetcher.stats.sthLatency, labels)
	if err != nil {
		t.Errorf("Unexpected error counting m.fetcher.stats.sthLatency samples: %s",
			err.Error())
	}
	if latencyObservations != 1 {
		t.Errorf("Expected m.fetcher.stats.sthLatency to have 1 sample, had %d",
			latencyObservations)
	}

	// Failures should increment the sthFailures counter
	failureMetric, err := test.CountCounterVecWithLabels(m.fetcher.stats.sthFailures, labels)
	if err != nil {
		t.Errorf("Unexpected error counting m.fetcher.stats.sthFailures countervec: %s",
			err.Error())
	}
	if failureMetric != 1 {
		t.Errorf("Expected m.fetcher.stats.sthFailures to be %d, was %d", 1, failureMetric)
	}

	// Replace the monitor's fetcher's client with one that returns a fixed STH generated
	// two hours in the past
	timestampAge := 2 * time.Hour
	sthTimestamp := clk.Now().Add(-timestampAge)
	m.fetcher.client = mockClient{
		timestamp: sthTimestamp,
	}
	// Make another STH observation
	m.fetcher.observeSTH()

	// There should be another latency observation sample
	latencyObservations, err = test.CountHistogramSamplesWithLabels(m.fetcher.stats.sthLatency, labels)
	if err != nil {
		t.Errorf("Unexpected error counting m.fetcher.stats.sthLatency samples: %s",
			err.Error())
	}
	if latencyObservations != 2 {
		t.Errorf("Expected m.fetcher.stats.sthLatency to have 2 samples, had %d",
			latencyObservations)
	}

	// The age Gauge should have the expected value
	ageValue, err := test.GaugeValueWithLabels(m.fetcher.stats.sthAge, labels)
	expectedAge := int(timestampAge.Seconds())
	if err != nil {
		t.Errorf("Unexpected error getting m.fetcher.stats.sthAge gauge value: %s",
			err.Error())
	}
	if ageValue != expectedAge {
		t.Errorf("Expected m.fetcher.stats.sthAge to be %d, was %d", expectedAge, ageValue)
	}

	// The timestamp Gauge should have the expected value
	tsValue, err := test.GaugeValueWithLabels(m.fetcher.stats.sthTimestamp, labels)
	expectedTSValue := int(sthTimestamp.UnixNano() / int64(time.Millisecond))
	if err != nil {
		t.Errorf("Unexpected error getting m.fetcher.stats.sthTimestamp gauge value: %s",
			err.Error())
	}
	if tsValue != expectedTSValue {
		t.Errorf("Expected m.fetcher.stats.sthTimestamp to be %d, was %d", expectedTSValue, tsValue)
	}
}

func TestSubmitCertificate(t *testing.T) {
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchDuration := time.Second
	certInterval := time.Second
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

	// Create a monitor configured with an certIssuer and certIssuerKey
	m, err := New(logURI, logKey, fetchDuration, certInterval, certIssuerKey, certIssuer, l, clk)
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
			m.submitter.submitCertificate()

			// There should always be a latency observation, regardless of whether the
			// testcase was expected to succeed or fail.
			labels := prometheus.Labels{"uri": logURI}
			latencyObservations, err := test.CountHistogramSamplesWithLabels(m.submitter.stats.certSubmitLatency, labels)
			// There should be 1 observation for each test case
			expectedLatencyObservations := i + 1
			if err != nil {
				t.Errorf("Unexpected error counting m.submitter.stats.certSubmitLatency samples: %s",
					err.Error())
			}
			if latencyObservations != expectedLatencyObservations {
				t.Errorf("Expected m.submitter.stats.certSubmitLatency to have %d sample, had %d",
					expectedLatencyObservations, latencyObservations)
			}

			// Increment one of the expected metrics based on whether the cert
			// submission was expected to pass or fail
			if tc.ExpectSuccess {
				successCount++
			} else {
				failCount++
			}

			failureLabels := prometheus.Labels{"uri": logURI, "status": "fail"}
			failureMetric, err := test.CountCounterVecWithLabels(m.submitter.stats.certSubmitResults, failureLabels)
			if err != nil {
				t.Errorf("Unexpected error counting m.submitter.stats.certSubmitResults countervec: %s",
					err.Error())
			}
			if failureMetric != failCount {
				t.Errorf("Expected m.submitter.stats.certSubmitResults fail count to be %d, was %d", failCount, failureMetric)
			}

			successLabels := prometheus.Labels{"uri": logURI, "status": "ok"}
			successMetric, err := test.CountCounterVecWithLabels(m.submitter.stats.certSubmitResults, successLabels)
			if err != nil {
				t.Errorf("Unexpected error counting m.submitter.stats.certSubmitResults countervec: %s",
					err.Error())
			}
			if successMetric != successCount {
				t.Errorf("Expected m.submitter.stats.certSubmitResults OK count to be %d, was %d", successCount, successMetric)
			}
		})
	}
}
