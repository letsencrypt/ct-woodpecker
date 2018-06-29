package monitor

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// sthFetchStats is a type to hold the prometheus metrics used by
// a sthFetcher
type sthFetchStats struct {
	sthTimestamp *prometheus.GaugeVec
	sthAge       *prometheus.GaugeVec
	sthFailures  *prometheus.CounterVec
	sthLatency   *prometheus.HistogramVec
}

// sthStats is a sthFetchStats instance with promauto registered
// prometheus metrics
var sthStats *sthFetchStats = &sthFetchStats{
	sthTimestamp: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sth_timestamp",
		Help: "Timestamp of observed CT log signed tree head (STH)",
	}, []string{"uri"}),
	sthAge: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sth_age",
		Help: "Elapsed time since observed CT log signed tree head (STH) timestamp",
	}, []string{"uri"}),
	sthFailures: promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sth_failures",
		Help: "Count of failures fetching CT log signed tree head (STH)",
	}, []string{"uri"}),
	sthLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sth_latency",
		Help:    "Latency observing CT log signed tree head (STH)",
		Buckets: internetFacingBuckets,
	}, []string{"uri"}),
}

// FetcherOptions is a struct holding options for STH fetching.
type FetcherOptions struct {
	// Interval describes the duration that the monitor will sleep between
	// fetching the STH.
	Interval time.Duration
	// Timeout is the STH fetch timeout.
	Timeout time.Duration
}

// Valid checks that the FetcherOptions interval is positive.
func (o FetcherOptions) Valid() error {
	if o.Interval <= 0 {
		return errors.New("Fetcher interval must be >= 0")
	}
	if o.Timeout <= 0 {
		return errors.New("Fetcher timeout must be >= 0")
	}
	return nil
}

// sthFetcher is a type for periodically fetching a log's STH and publishing
// metrics about it.
type sthFetcher struct {
	logger *log.Logger
	clk    clock.Clock
	client monitorCTClient
	logURI string
	stats  *sthFetchStats

	stopChannel chan bool

	// How long to sleep between fetching the log's current STH
	sthFetchInterval time.Duration
	// How long to wait before giving up on an STH fetch
	sthTimeout time.Duration
}

// Run starts the log STH fetching process by creating a goroutine that will loop
// forever fetching the log's STH in a goroutine and then sleeping.
func (f *sthFetcher) run() {
	go func() {
		for {
			go f.observeSTH()
			f.logger.Printf("Sleeping for %s before next STH check\n", f.sthFetchInterval)
			select {
			case <-f.stopChannel:
				return
			case <-time.After(f.sthFetchInterval):
			}
		}
	}()
}

func (f *sthFetcher) stop() {
	f.logger.Printf("Stopping %s sthFetcher", f.logURI)
	f.stopChannel <- true
}

// observeSTH fetches a monitored log's signed tree head (STH). The latency of
// this operation is published to the `sth_latency` metric. The clocktime elapsed
// since the STH's timestamp is published to the `sth_age` metric. If an error
// occurs the `sth_failures` metric will be incremented. If the operation
// succeeds then the `sth_timestamp` gauge will be updated to the returned STH's
// timestamp.
func (f *sthFetcher) observeSTH() {
	labels := prometheus.Labels{"uri": f.logURI}
	f.logger.Printf("Fetching STH for %q\n", f.logURI)

	start := f.clk.Now()
	ctx, cancel := context.WithTimeout(context.Background(), f.sthTimeout)
	defer cancel()
	sth, err := f.client.GetSTH(ctx)
	elapsed := f.clk.Since(start)
	f.stats.sthLatency.With(labels).Observe(elapsed.Seconds())

	if err != nil {
		f.logger.Printf("!! Error fetching STH: %s\n", err.Error())
		f.stats.sthFailures.With(labels).Inc()
		return
	}

	f.stats.sthTimestamp.With(labels).Set(float64(sth.Timestamp))
	ts := time.Unix(0, int64(sth.Timestamp)*int64(time.Millisecond))
	sthAge := f.clk.Since(ts)
	f.stats.sthAge.With(labels).Set(sthAge.Seconds())

	f.logger.Printf("STH for %q verified. Timestamp: %s Age: %s\n", f.logURI, ts, sthAge)
}
