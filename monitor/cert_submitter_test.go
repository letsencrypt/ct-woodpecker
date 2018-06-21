package monitor

import (
	"log"
	"strconv"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/letsencrypt/ct-woodpecker/test"
	"github.com/prometheus/client_golang/prometheus"
)

func assertLatencySamples(t *testing.T, logURI string, precert bool, expected int, histogram *prometheus.HistogramVec) {
	labels := prometheus.Labels{"uri": logURI, "precert": strconv.FormatBool(precert)}
	latencyObservations, err := test.CountHistogramSamplesWithLabels(histogram, labels)
	if err != nil {
		t.Errorf("Unexpected error counting latency histogram samples: %s",
			err.Error())
	}
	if latencyObservations != expected {
		t.Errorf("Expected %d latency histogram samples. Found %d",
			expected, latencyObservations)
	}
}

func assertResultsCount(t *testing.T, logURI string, precert bool, success bool, expected int, counter *prometheus.CounterVec) {
	status := "fail"
	if success {
		status = "ok"
	}
	labels := prometheus.Labels{"uri": logURI, "status": status, "precert": strconv.FormatBool(precert)}

	count, err := test.CountCounterVecWithLabels(counter, labels)
	if err != nil {
		t.Errorf("Unexpected error counting CounterVec: %s", err.Error())
	}
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
		}, l, clk)
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
			assertResultsCount(t, logURI, true, false, failCount, m.submitter.stats.certSubmitResults)
			// and the correct number of failed cert submissions
			assertResultsCount(t, logURI, false, false, failCount, m.submitter.stats.certSubmitResults)

			// There should also be the correct number of successful precert submissions
			assertResultsCount(t, logURI, true, true, successCount, m.submitter.stats.certSubmitResults)
			// and the correct number of successful cert submissions
			assertResultsCount(t, logURI, false, true, successCount, m.submitter.stats.certSubmitResults)
		})
	}
}
