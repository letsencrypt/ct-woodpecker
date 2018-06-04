package monitor

import (
	"log"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/letsencrypt/ct-woodpecker/test"
	"github.com/prometheus/client_golang/prometheus"
)

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
