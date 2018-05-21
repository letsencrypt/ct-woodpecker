package monitor

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	ctClient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// monitorStat is a struct collecting up various prometheus metrics a monitor
// will export/track.
type monitorStats struct {
	sthTimestamp *prometheus.GaugeVec
	sthFailures  *prometheus.CounterVec
	sthLatency   *prometheus.HistogramVec
}

const (
	// sthTimeout controls how long should each STH fetch wait before timing out
	sthTimeout = time.Second * 15
)

var (
	// internetFacingBuckets are histogram buckets suitable for measuring
	// latencies that involve traversing the public internet.
	internetFacingBuckets               = []float64{.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45}
	stats                 *monitorStats = &monitorStats{
		sthTimestamp: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sth_timestamp",
			Help: "Timestamp of observed CT log signed tree head (STH)",
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
)

// Monitor is a struct for monitoring a CT log.
type Monitor struct {
	logger *log.Logger
	clk    clock.Clock
	stats  *monitorStats
	logURI string
	logKey string
	client *ctClient.LogClient
	// How long to sleep between fetching the log's current STH
	sthFetchInterval time.Duration
}

// New creates a Monitor for the given parameters. The b64key parameter is
// expected to contain the PEM encoded public key used to verify the log's STH
// _without_ the PEM header/footer.
func New(
	uri, b64key string,
	sthFetchInterval time.Duration,
	logger *log.Logger,
	clk clock.Clock) (*Monitor, error) {
	hc := &http.Client{
		Timeout: time.Minute,
	}

	// By convention CT log public keys are shared/configured as the base64
	// encoded PEM content of the key _without_ the PEM object type header/footer.
	// The `ctclient.New()` constructor expects a vanilla PEM block that includes
	// the header/footer so we manufacture that here with the b64key
	pubkey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", b64key)

	// Create a CT client for the log. We pass a PublicKey in the
	// `jsonclient.Options` to ensure that the STH signature will be validated
	// when we call the client's `GetSTH` function. If this parameter is nil no
	// signature check is performed.
	client, err := ctClient.New(uri, hc, jsonclient.Options{
		Logger:    logger,
		PublicKey: pubkey,
	})
	if err != nil {
		return nil, err
	}

	return &Monitor{
		logger:           logger,
		clk:              clk,
		stats:            stats,
		logURI:           uri,
		logKey:           pubkey,
		client:           client,
		sthFetchInterval: sthFetchInterval,
	}, nil
}

// observeSTH fetches the monitored log's signed tree head (STH). The latency of
// this operation is published to the `sthLatency` metric. If an error occurs
// the `sthFailures` metric will be incremented. If the operation succeeds then
// the `sthTimestamp` gauge will be updated to the returned STH's timestamp.
func (m *Monitor) observeSTH() {
	labels := prometheus.Labels{"uri": m.logURI}
	m.logger.Printf("Fetching STH for %q\n", m.logURI)

	start := m.clk.Now()
	ctx, _ := context.WithTimeout(context.Background(), sthTimeout)
	sth, err := m.client.GetSTH(ctx)
	elapsed := m.clk.Since(start)
	m.stats.sthLatency.With(labels).Observe(elapsed.Seconds())

	if err != nil {
		m.logger.Printf("!! Error fetching STH: %#v\n", err)
		m.stats.sthFailures.With(labels).Inc()
		return
	}

	m.stats.sthTimestamp.With(labels).Set(float64(sth.Timestamp))
	ts := time.Unix(0, int64(sth.Timestamp)*int64(time.Millisecond))
	m.logger.Printf("STH for %q verified. Timestamp: %s\n", m.logURI, ts)
}

// Run starts the log monitoring process by creating a Go routine that will loop
// forever fetching the log's STH and then sleeping.
func (m *Monitor) Run() {
	go func() {
		for {
			m.observeSTH()
			m.logger.Printf("Sleeping for %s\n", m.sthFetchInterval)
			time.Sleep(m.sthFetchInterval)
		}
	}()
}
