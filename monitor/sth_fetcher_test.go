package monitor

import (
	"log"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/test"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/transparency-dev/merkle"
)

func TestObserveSTH(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchDuration := time.Second
	logURI := "test"
	labels := prometheus.Labels{"uri": logURI}

	m, err := New(
		Options{
			LogURI: logURI,
			LogKey: logKey,
			FetchOpts: &FetcherOptions{
				Interval: fetchDuration,
				Timeout:  time.Second,
			},
		}, l, l, clk)
	if err != nil {
		t.Fatalf("Unexpected error from New(): %s", err.Error())
	}

	// Replace the monitor's fetcher's client with one that always fails
	m.fetcher.client = errorClient{}
	// Make an STH observation
	m.fetcher.observeSTH()

	// Check STH fetches are counted
	if fetchObservations := test.CountCounterVecWithLabels(m.fetcher.stats.sthFetchTotal, labels); fetchObservations != 1 {
		t.Errorf("Expected m.fetcher.stats.sthFetchTotal to have 1 sample, had %d",
			fetchObservations)
	}

	// Failures should have a latency observation
	latencyObservations := test.CountHistogramSamplesWithLabels(m.fetcher.stats.sthLatency, labels)
	if latencyObservations != 1 {
		t.Errorf("Expected m.fetcher.stats.sthLatency to have 1 sample, had %d",
			latencyObservations)
	}

	// Failures should increment the sthFailures counter
	failureMetric := test.CountCounterVecWithLabels(m.fetcher.stats.sthFailures, labels)
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

	// There should be another fetch observation sample
	if fetchObservations := test.CountCounterVecWithLabels(m.fetcher.stats.sthFetchTotal, labels); fetchObservations != 2 {
		t.Errorf("Expected m.fetcher.stats.sthFetchTotal to have 2 samples, had %d",
			fetchObservations)
	}

	// There should be another latency observation sample
	latencyObservations = test.CountHistogramSamplesWithLabels(m.fetcher.stats.sthLatency, labels)
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

	// The previous STH should be set correctly
	if m.fetcher.prevSTH == nil {
		t.Fatalf("Expected non-nil m.fetcher.prevSTH, was nil")
	}
	actualTS := int64(m.fetcher.prevSTH.Timestamp)
	expectedTS := sthTimestamp.UnixNano() / int64(time.Millisecond)
	if actualTS != expectedTS {
		t.Errorf("Expected m.fetcher.prevSTH.Timestamp to be %d was %d\n",
			expectedTS, actualTS)
	}
}

// MockVerifyConsistency is a fake function with the same signature as
// proof.VerifyConsistency, so it can be substituted for that function.
func MockVerifyConsistency(_ merkle.LogHasher, _, _ uint64, _ [][]byte, _, _ []byte) error {
	// mockVerifier does not actual verification and returns nil to indicate
	// everything is a-OK
	return nil
}

func TestVerifySTHConsistency(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchInterval := time.Second
	logURI := "test"

	// Create a fetcher backed by an errorClient
	f := newSTHFetcher(monitorCheck{
		logURI: logURI,
		stdout: l,
		stderr: l,
		clk:    clk,
	},
		&FetcherOptions{
			Interval: fetchInterval,
			Timeout:  time.Second,
		},
		errorClient{})

	first := &ct.SignedTreeHead{
		TreeSize:       1337,
		SHA256RootHash: ct.SHA256Hash{0x1D, 0xEA, 0x1},
	}
	second := &ct.SignedTreeHead{
		TreeSize:       first.TreeSize,
		SHA256RootHash: ct.SHA256Hash{0xD1, 0x5B, 0xE1, 0x1E, 0xF},
	}

	// Verifying the consistency between two STHs that have the same treesize and
	// different hashes should increment the inconsistencies stat with the correct
	// type label and not increment the latency stat
	f.verifySTHConsistency(first, second)
	inequalHashLabels := prometheus.Labels{"uri": logURI, "type": "equal-treesize-inequal-hash"}
	failureMetric := test.CountCounterVecWithLabels(f.stats.sthInconsistencies, inequalHashLabels)
	expectedFailures := 1
	if failureMetric != expectedFailures {
		t.Errorf("Expected m.fetcher.stats.sthInconsistencies to be %d, was %d",
			expectedFailures, failureMetric)
	}
	latencyLabels := prometheus.Labels{"uri": logURI}
	latencySamples := test.CountHistogramSamplesWithLabels(f.stats.sthProofLatency, latencyLabels)
	expectedLatencySamples := 0
	if latencySamples != expectedLatencySamples {
		t.Errorf("Expected %d m.fetcher.stats.sthProofLatency samples, found %d", expectedLatencySamples, latencySamples)
	}

	// Change the second STH's hash to match the first's
	second.SHA256RootHash = first.SHA256RootHash

	// Verifying the consistency between two STHs that have the same treesize and
	// the same hashes should not increment the inconsistencies stat or the
	// number of latency observations
	f.verifySTHConsistency(first, second)
	failureMetric = test.CountCounterVecWithLabels(f.stats.sthInconsistencies, inequalHashLabels)
	if failureMetric != expectedFailures {
		t.Errorf("Expected m.fetcher.stats.sthInconsistencies to be %d, was %d",
			expectedFailures, failureMetric)
	}
	latencySamples = test.CountHistogramSamplesWithLabels(f.stats.sthProofLatency, latencyLabels)
	if latencySamples != expectedLatencySamples {
		t.Errorf("Expected %d m.fetcher.stats.sthProofLatency samples, found %d", expectedLatencySamples, latencySamples)
	}

	// Verifying the consistency between a STHs of treesize zero and
	// another STH should not increment the inconsistencies stat or the
	// number of latency observations. To verify STH consistency first must be
	// 0 < first < second.
	first.TreeSize = 0
	f.verifySTHConsistency(first, second)
	failureMetric = test.CountCounterVecWithLabels(f.stats.sthInconsistencies, inequalHashLabels)
	if failureMetric != expectedFailures {
		t.Errorf("Expected m.fetcher.stats.sthInconsistencies to be %d, was %d",
			expectedFailures, failureMetric)
	}
	latencySamples = test.CountHistogramSamplesWithLabels(f.stats.sthProofLatency, latencyLabels)
	if latencySamples != expectedLatencySamples {
		t.Errorf("Expected %d m.fetcher.stats.sthProofLatency samples, found %d", expectedLatencySamples, latencySamples)
	}
	first.TreeSize = 1337

	// Change the second STH's tree size and hash so there is a reason to fetch a consistency proof
	second.TreeSize = 7331
	second.SHA256RootHash = ct.SHA256Hash{0xD1, 0x5B, 0xE1, 0x1E, 0xF}

	// Verifying the consistency between two STHs with the errorClient should
	// increment the inconsistencies stat and the number of latency observations
	f.verifySTHConsistency(first, second)
	proofGetFailureLabels := prometheus.Labels{"uri": logURI, "type": "failed-to-get-proof"}
	failureMetric = test.CountCounterVecWithLabels(f.stats.sthInconsistencies, proofGetFailureLabels)
	expectedFailures = 1
	if failureMetric != expectedFailures {
		t.Errorf("Expected m.fetcher.stats.sthInconsistencies to be %d, was %d",
			expectedFailures, failureMetric)
	}
	latencySamples = test.CountHistogramSamplesWithLabels(f.stats.sthProofLatency, latencyLabels)
	expectedLatencySamples = 1
	if latencySamples != expectedLatencySamples {
		t.Errorf("Expected %d m.fetcher.stats.sthProofLatency samples, found %d", expectedLatencySamples, latencySamples)
	}

	// Replace the fetcher client with one that returns a bogus proof when asked
	f.client = mockClient{proof: [][]byte{{0xFA, 0xCA, 0xDE}}}

	// Verifying the consistency between two STHs with the mockClient should
	// increment the inconsistencies stat and the number of latency observations
	f.verifySTHConsistency(first, second)
	badProofLabels := prometheus.Labels{"uri": logURI, "type": "failed-to-verify-proof"}
	failureMetric = test.CountCounterVecWithLabels(f.stats.sthInconsistencies, badProofLabels)
	expectedFailures = 1
	if failureMetric != expectedFailures {
		t.Errorf("Expected m.fetcher.stats.sthInconsistencies to be %d, was %d",
			expectedFailures, failureMetric)
	}
	latencySamples = test.CountHistogramSamplesWithLabels(f.stats.sthProofLatency, latencyLabels)
	expectedLatencySamples++
	if latencySamples != expectedLatencySamples {
		t.Errorf("Expected %d m.fetcher.stats.sthProofLatency samples, found %d", expectedLatencySamples, latencySamples)
	}

	// Replace the fetcher's verifier with one that assumes any proof is valid
	f.verify = MockVerifyConsistency

	// Verifying the consistency between two STHs using the mock verifier should
	// not increment the inconsistencies stat but it should increment the number
	// of latency observations
	f.verifySTHConsistency(first, second)
	failureMetric = test.CountCounterVecWithLabels(f.stats.sthInconsistencies, badProofLabels)
	if failureMetric != expectedFailures {
		t.Errorf("Expected m.fetcher.stats.sthInconsistencies to be %d, was %d",
			expectedFailures, failureMetric)
	}
	latencySamples = test.CountHistogramSamplesWithLabels(f.stats.sthProofLatency, latencyLabels)
	expectedLatencySamples++
	if latencySamples != expectedLatencySamples {
		t.Errorf("Expected %d m.fetcher.stats.sthProofLatency samples, found %d", expectedLatencySamples, latencySamples)
	}
}

func TestStaleSTHHandling(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchInterval := time.Second
	logURI := "test"

	var stdErr test.SafeBuffer
	stdErrLogger := log.New(&stdErr, "TestStaleSTHHandling", log.LstdFlags)

	f := newSTHFetcher(monitorCheck{
		logURI: logURI,
		stdout: l,
		stderr: stdErrLogger,
		clk:    clk,
	},
		&FetcherOptions{
			Interval: fetchInterval,
			Timeout:  time.Second,
		},
		errorClient{})
	f.verify = MockVerifyConsistency

	// First return a 2 hour old STH
	timestampAge := 2 * time.Hour
	sthTimestamp := clk.Now().Add(-timestampAge)
	f.client = mockClient{
		timestamp: sthTimestamp,
		treesize:  10,
	}

	// Observe the STH and verify prevSTH is set correctly
	f.observeSTH()
	if f.prevSTH == nil {
		t.Fatalf("Expected prevSTH to be set")
	}
	if f.prevSTH.TreeSize != 10 {
		t.Errorf("Expected prevSTH to have treesize %d, got %d", 10, f.prevSTH.TreeSize)
	}
	if stdErrOut := stdErr.String(); stdErrOut != "" {
		t.Errorf("Expected stderr to be empty, was %q\n", stdErrOut)
	}

	// Now return a 1 hour old STH for a larger treesize
	timestampAge = 1 * time.Hour
	sthTimestamp = clk.Now().Add(-timestampAge)
	f.client = mockClient{
		timestamp: sthTimestamp,
		treesize:  20,
		proof:     [][]byte{{0xFA, 0xCA, 0xDE}},
	}

	// Observe the STH and verify prevSTH is set correctly
	f.observeSTH()
	if f.prevSTH == nil {
		t.Fatalf("Expected prevSTH to be set")
	}
	if f.prevSTH.TreeSize != 20 {
		t.Errorf("Expected prevSTH to have treesize %d, got %d", 20, f.prevSTH.TreeSize)
	}
	if stdErrOut := stdErr.String(); stdErrOut != "" {
		t.Errorf("Expected stderr to be empty, was %q\n", stdErrOut)
	}

	// Return a stale STH within the log's MMD.
	timestampAge = 10 * time.Hour
	sthTimestamp = clk.Now().Add(-timestampAge)
	f.client = mockClient{
		timestamp: sthTimestamp,
		treesize:  5,
	}

	// Observe the STH and verify prevSTH is set correctly
	f.observeSTH()
	if f.prevSTH == nil {
		t.Fatalf("Expected prevSTH to be set")
	}
	// The prevSTH should still be for treesize 20
	if f.prevSTH.TreeSize != 20 {
		t.Errorf("Expected prevSTH to have treesize %d, got %d", 20, f.prevSTH.TreeSize)
	}
	if stdErrOut := stdErr.String(); stdErrOut != "" {
		t.Errorf("Expected stderr to be empty, was %q\n", stdErrOut)
	}

	// Return a stale STH outside the log's MMD.
	timestampAge = (24 * time.Hour) * 30
	sthTimestamp = clk.Now().Add(-timestampAge)
	f.client = mockClient{
		timestamp: sthTimestamp,
		treesize:  1,
	}
	// Observe the STH and verify prevSTH is set correctly
	f.observeSTH()
	if f.prevSTH == nil {
		t.Fatalf("Expected prevSTH to be set")
	}
	// The prevSTH should still be for treesize 20
	if f.prevSTH.TreeSize != 20 {
		t.Errorf("Expected prevSTH to have treesize %d, got %d", 20, f.prevSTH.TreeSize)
	}
	if stdErrOut := stdErr.String(); stdErrOut != "" {
		t.Errorf("Expected stderr to be empty, was %q\n", stdErrOut)
	}
}
