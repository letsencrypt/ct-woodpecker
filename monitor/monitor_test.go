package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/helpers"
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
	processedLogKey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", logKey)
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

	if m.logURI != logURI {
		t.Errorf("Expected monitor logURI to be %q, got %q", logURI, m.logURI)
	}

	if m.logKey != processedLogKey {
		t.Errorf("Expected monitor logKey %q, got %q", processedLogKey, m.logKey)
	}

	if m.sthFetchInterval != fetchDuration {
		t.Errorf("Expected monitor sthFetchDuration %s got %s", m.sthFetchInterval, fetchDuration)
	}

	if m.certSubmitInterval != certInterval {
		t.Errorf("Expected monitor certSubmitInterval %s got %s", m.certSubmitInterval, certInterval)
	}

	if m.stats == nil {
		t.Error("Expected monitor stats to be non-nil")
	}

	if m.client == nil {
		t.Errorf("Expected monitor client to be non-nil")
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

	// Replace the monitor's client with one that always fails
	m.client = errorClient{}
	// Make an STH observation
	m.observeSTH()

	// Failures should have a latency observation
	latencyObservations, err := test.CountHistogramSamplesWithLabels(m.stats.sthLatency, labels)
	if err != nil {
		t.Errorf("Unexpected error counting m.stats.sthLatency samples: %s",
			err.Error())
	}
	if latencyObservations != 1 {
		t.Errorf("Expected m.stats.sthLatency to have 1 sample, had %d",
			latencyObservations)
	}

	// Failures should increment the sthFailures counter
	failureMetric, err := test.CountCounterVecWithLabels(m.stats.sthFailures, labels)
	if err != nil {
		t.Errorf("Unexpected error counting m.stats.sthFailures countervec: %s",
			err.Error())
	}
	if failureMetric != 1 {
		t.Errorf("Expected m.stats.sthFailures to be %d, was %d", 1, failureMetric)
	}

	// Replace the monitor's client with one that returns a fixed STH generated
	// two hours in the past
	timestampAge := 2 * time.Hour
	sthTimestamp := clk.Now().Add(-timestampAge)
	m.client = mockClient{
		timestamp: sthTimestamp,
	}
	// Make another STH observation
	m.observeSTH()

	// There should be another latency observation sample
	latencyObservations, err = test.CountHistogramSamplesWithLabels(m.stats.sthLatency, labels)
	if err != nil {
		t.Errorf("Unexpected error counting m.stats.sthLatency samples: %s",
			err.Error())
	}
	if latencyObservations != 2 {
		t.Errorf("Expected m.stats.sthLatency to have 2 samples, had %d",
			latencyObservations)
	}

	// The age Gauge should have the expected value
	ageValue, err := test.GaugeValueWithLabels(m.stats.sthAge, labels)
	expectedAge := int(timestampAge.Seconds())
	if err != nil {
		t.Errorf("Unexpected error getting m.stats.sthAge gauge value: %s",
			err.Error())
	}
	if ageValue != expectedAge {
		t.Errorf("Expected m.stats.sthAge to be %d, was %d", expectedAge, ageValue)
	}

	// The timestamp Gauge should have the expected value
	tsValue, err := test.GaugeValueWithLabels(m.stats.sthTimestamp, labels)
	expectedTSValue := int(sthTimestamp.UnixNano() / int64(time.Millisecond))
	if err != nil {
		t.Errorf("Unexpected error getting m.stats.sthTimestamp gauge value: %s",
			err.Error())
	}
	if tsValue != expectedTSValue {
		t.Errorf("Expected m.stats.sthTimestamp to be %d, was %d", expectedTSValue, tsValue)
	}
}

func TestSubmitCertificate(t *testing.T) {
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchDuration := time.Second
	certInterval := time.Second
	logURI := "test"
	labels := prometheus.Labels{"uri": logURI}

	// Create a logger backed by the safeBuffer. The log.Logger type is only safe
	// for concurrent use when the backing buffer is. Using a raw bytes.Buffer
	// with a shared logger will cause data races.
	var out test.SafeBuffer
	l := log.New(&out, "TestSubmitCertificate ", log.LstdFlags)

	certIssuer, err := helpers.LoadCertificate("../test/issuer.pem")
	if err != nil {
		t.Fatalf("Error loading issuer cert: %s", err.Error())
	}
	certIssuerKey, err := helpers.LoadPrivateKey("../test/issuer.key")
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
			m.client = tc.MockClient
			m.submitCertificate()

			// There should always be a latency observation, regardless of whether the
			// testcase was expected to succeed or fail.
			latencyObservations, err := test.CountHistogramSamplesWithLabels(m.stats.certSubmitLatency, labels)
			// There should be 1 observation for each test case
			expectedLatencyObservations := i + 1
			if err != nil {
				t.Errorf("Unexpected error counting m.stats.certSubmitLatency samples: %s",
					err.Error())
			}
			if latencyObservations != expectedLatencyObservations {
				t.Errorf("Expected m.stats.certSubmitLatency to have %d sample, had %d",
					expectedLatencyObservations, latencyObservations)
			}

			// Increment one of the expected metrics based on whether the cert
			// submission was expected to pass or fail
			if tc.ExpectSuccess {
				successCount++
			} else {
				failCount++
			}

			failureMetric, err := test.CountCounterVecWithLabels(m.stats.certSubmitFailures, labels)
			if err != nil {
				t.Errorf("Unexpected error counting m.stats.certSubmitFailures countervec: %s",
					err.Error())
			}
			if failureMetric != failCount {
				t.Errorf("Expected m.stats.certSubmitFailures to be %d, was %d", failCount, failureMetric)
			}

			successMetric, err := test.CountCounterVecWithLabels(m.stats.certSubmitSuccesses, labels)
			if err != nil {
				t.Errorf("Unexpected error counting m.stats.certSubmitSucesses countervec: %s",
					err.Error())
			}
			if successMetric != successCount {
				t.Errorf("Expected m.stats.certSubmitSuccesses to be %d, was %d", successCount, successMetric)
			}
		})
	}
}
