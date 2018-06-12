package monitor

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/test"
	"github.com/prometheus/client_golang/prometheus"
)

func TestObserveSTH(t *testing.T) {
	l := log.New(os.Stdout, "", log.LstdFlags)
	clk := clock.NewFake()
	clk.Set(time.Now())
	fetchDuration := time.Second
	logURI := "test"
	labels := prometheus.Labels{"uri": logURI}

	m, err := New(
		MonitorOptions{
			LogURI: logURI,
			LogKey: logKey,
			FetchOpts: &FetcherOptions{
				Interval: fetchDuration,
			},
		}, l, clk)
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
