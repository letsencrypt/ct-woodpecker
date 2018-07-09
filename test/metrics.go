package test

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_model/go"
)

// CountCounterVecWithLabels returns the current count a prometheus CounterVec
// with the given labels, or an error if there was a problem collecting the
// value.
func CountCounterVecWithLabels(counterVec *prometheus.CounterVec, labels prometheus.Labels) (int, error) {
	vec := counterVec.With(labels)
	ch := make(chan prometheus.Metric, 10)
	vec.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		return 0, fmt.Errorf("timed out collecting gauge metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)
	return int(iom.Counter.GetValue()), nil
}

func MustCountCounterVecWithLabels(counterVec *prometheus.CounterVec, labels prometheus.Labels) int {
	count, err := CountCounterVecWithLabels(counterVec, labels)
	if err != nil {
		panic(fmt.Sprintf("failed to get countervec counter: %#v", err))
	}
	return count
}

// GaugeValueWithLabels returns the current value with the provided labels from the
// the GaugeVec argument, or an error if there was a problem collecting the value.
func GaugeValueWithLabels(vecGauge *prometheus.GaugeVec, labels prometheus.Labels) (int, error) {
	gauge, err := vecGauge.GetMetricWith(labels)
	if err != nil {
		return 0, err
	}

	ch := make(chan prometheus.Metric, 10)
	gauge.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		return 0, fmt.Errorf("timed out collecting gauge metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)

	return int(iom.Gauge.GetValue()), nil
}

// CountHistogramSamplesWithLabels returns the number of samples a given prometheus
// Histogram has seen with the given labels, or an error if there was a problem
// collecting the sample count.
func CountHistogramSamplesWithLabels(histVec *prometheus.HistogramVec, labels prometheus.Labels) (int, error) {
	obs, err := histVec.GetMetricWith(labels)
	if err != nil {
		return 0, err
	}
	// prometheus.HistogramVec.GetMetricWith returns an Observer interface we must
	// cast to a Histogram in order to collect stats
	hist := obs.(prometheus.Histogram)
	if err != nil {
		return 0, err
	}
	ch := make(chan prometheus.Metric, 10)
	hist.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		return 0, fmt.Errorf("timed out collecting metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)
	return int(iom.Histogram.GetSampleCount()), nil
}

func MustCountHistogramSamplesWithLabels(histVec *prometheus.HistogramVec, labels prometheus.Labels) int {
	count, err := CountHistogramSamplesWithLabels(histVec, labels)
	if err != nil {
		panic(fmt.Sprintf("failed to get histogram samples: %#v", err))
	}
	return count
}
