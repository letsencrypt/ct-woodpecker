package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctClient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// monitorStat is a struct collecting up various prometheus metrics a monitor
// will export/track.
type monitorStats struct {
	sthTimestamp *prometheus.GaugeVec
	sthAge       *prometheus.GaugeVec
	sthFailures  *prometheus.CounterVec
	sthLatency   *prometheus.HistogramVec

	certSubmitLatency   *prometheus.HistogramVec
	certSubmitFailures  *prometheus.CounterVec
	certSubmitSuccesses *prometheus.CounterVec
}

const (
	// sthTimeout controls how long each STH fetch should wait before timing out
	sthTimeout = time.Second * 15
	// submitTimeout controls how long each certificate chain submission should
	// wait before timing out
	submitTimeout = time.Second * 15
	// requiredSCTFreshness indicates how fresh a timestamp in a returned SCT must
	// be for it to be considered valid.
	requiredSCTFreshness = time.Minute * 10
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
		certSubmitLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cert_submit_latency",
			Help:    "Latency submitting certificate chains to CT logs",
			Buckets: internetFacingBuckets,
		}, []string{"uri"}),
		certSubmitFailures: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_submit_failures",
			Help: "Count of failures submitting certificate chains to CT logs",
		}, []string{"uri"}),
		certSubmitSuccesses: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_submit_successes",
			Help: "Count of successes submitting certificate chains to CT logs",
		}, []string{"uri"}),
	}
)

// monitorCTClient is an interface that specifies the ctClient.LogClient
// functions that the monitor package uses. This interface allows for easy
// shimming of client methods with mock implementations for unit testing.
type monitorCTClient interface {
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	AddChain(context.Context, []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
}

// Monitor is a struct for monitoring a CT log.
type Monitor struct {
	logger *log.Logger
	clk    clock.Clock
	stats  *monitorStats
	logURI string
	logKey string
	client monitorCTClient
	// How long to sleep between fetching the log's current STH
	sthFetchInterval time.Duration
	// How long to sleep between submitting certificates to the log
	certSubmitInterval time.Duration
	// ECDSA private key used to issue certificates to submit to the log. Nil if
	// no certificates are to be submitted to the log.
	certIssuerKey *ecdsa.PrivateKey
	// Certificate used as the issuer for certificates submitted to the log. Nil
	// if no certificates are to be submitted to the log. The Certificate's public
	// key must correspond to the private key in certIssuerKey.
	certIssuer *x509.Certificate
}

// New creates a Monitor for the given parameters. The b64key parameter is
// expected to contain the PEM encoded public key used to verify the log's STH
// _without_ the PEM header/footer.
func New(
	uri, b64key string,
	sthFetchInterval, certSubmitInterval time.Duration,
	certIssuerKey *ecdsa.PrivateKey,
	certIssuer *x509.Certificate,
	logger *log.Logger,
	clk clock.Clock) (*Monitor, error) {
	hc := &http.Client{
		Timeout: time.Minute,
	}

	// By convention CT log public keys are shared/configured in base64 encoded
	// DER. The `ctclient.New()` constructor expects a vanilla PEM block, that is,
	// base64 encoded DER surronded by a header/footer. We manufacture such
	// a block here using the b64key
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
		logger:             logger,
		clk:                clk,
		stats:              stats,
		logURI:             uri,
		logKey:             pubkey,
		client:             client,
		sthFetchInterval:   sthFetchInterval,
		certSubmitInterval: certSubmitInterval,
		certIssuer:         certIssuer,
		certIssuerKey:      certIssuerKey,
	}, nil
}

// observeSTH fetches the monitored log's signed tree head (STH). The latency of
// this operation is published to the `sthLatency` metric. The clocktime elapsed
// since the STH's timestamp is published to the `sthAge` metric. If an error
// occurs the `sthFailures` metric will be incremented. If the operation
// succeeds then the `sthTimestamp` gauge will be updated to the returned STH's
// timestamp.
func (m *Monitor) observeSTH() {
	labels := prometheus.Labels{"uri": m.logURI}
	m.logger.Printf("Fetching STH for %q\n", m.logURI)

	start := m.clk.Now()
	ctx, cancel := context.WithTimeout(context.Background(), sthTimeout)
	defer cancel()
	sth, err := m.client.GetSTH(ctx)
	elapsed := m.clk.Since(start)
	m.stats.sthLatency.With(labels).Observe(elapsed.Seconds())

	if err != nil {
		m.logger.Printf("!! Error fetching STH: %s\n", err.Error())
		m.stats.sthFailures.With(labels).Inc()
		return
	}

	m.stats.sthTimestamp.With(labels).Set(float64(sth.Timestamp))
	ts := time.Unix(0, int64(sth.Timestamp)*int64(time.Millisecond))
	sthAge := m.clk.Since(ts)
	m.stats.sthAge.With(labels).Set(sthAge.Seconds())

	m.logger.Printf("STH for %q verified. Timestamp: %s Age: %s\n", m.logURI, ts, sthAge)
}

// submitCertificate issues a certificate with the monitor's
// certIssuer/certIssuerKey and submits it to the monitored log's add-chain
// endpoint. The latency of the submission is tracked in the
// `cert_submit_latency` prometheus histogram. If the submission fails, or the
// returned SCT is invalid the `cert_submit_failures` prometheus countervec is
// incremented. If the submission succeeds the `cert_submit_successes`
// prometheus countervec is  incremented. An SCT is considered invalid if the
// signature does not validate, or if the timestamp is too far in the future or
// the past (controlled by `requiredSCTFreshness`).
func (m *Monitor) submitCertificate() {
	labels := prometheus.Labels{"uri": m.logURI}
	m.logger.Printf("Submitting certificate to %q\n", m.logURI)

	cert, err := pki.IssueTestCertificate(m.certIssuerKey, m.certIssuer, m.clk)
	if err != nil {
		// This should not occur and if it does we should abort hard
		panic(fmt.Sprintf("!!! Error issuing certificate: %s\n", err.Error()))
	}

	// Because ct-woodpecker issues directly off of a fake root the "chain" only
	// contains the leaf certificate we minted in issueCertificate()
	chain := []ct.ASN1Cert{
		ct.ASN1Cert{Data: cert.Raw},
	}

	start := m.clk.Now()
	ctx, cancel := context.WithTimeout(context.Background(), submitTimeout)
	defer cancel()
	sct, err := m.client.AddChain(ctx, chain)
	elapsed := m.clk.Since(start)
	m.stats.certSubmitLatency.With(labels).Observe(elapsed.Seconds())

	if err != nil {
		m.logger.Printf("!!! Error submitting certificate to %q: %s\n", m.logURI, err.Error())
		m.stats.certSubmitFailures.With(labels).Inc()
		return
	}

	ts := time.Unix(0, int64(sct.Timestamp)*int64(time.Millisecond))
	sctAge := m.clk.Since(ts)

	// Check that the SCT's timestamp is within an allowable tolerance into the
	// future and the past. The SCT's signature & log ID have already been verified by
	// `m.client.AddChain()`
	if sctAge > requiredSCTFreshness {
		m.logger.Printf("!!! Error submitting certificate to %q: returned SCT timestamp signed %s in the future (expected < %s)",
			m.logURI, sctAge, requiredSCTFreshness)
		m.stats.certSubmitFailures.With(labels).Inc()
		return
	} else if sctAge < -requiredSCTFreshness {
		m.logger.Printf("!!! Error submitting certificate to %q: returned SCT timestamp signed %s in the past (expected > %s)",
			m.logURI, sctAge, requiredSCTFreshness)
		m.stats.certSubmitFailures.With(labels).Inc()
		return
	}

	m.stats.certSubmitSuccesses.With(labels).Inc()
	m.logger.Printf("Certificate chain submitted to %q. SCT timestamp %s", m.logURI, ts)
}

// Run starts the log monitoring process by creating a goroutine that will loop
// forever fetching the log's STH and then sleeping as well as a goroutine that
// will submit certs forever and then sleeping (if m.certIssuerKey is not nil).
func (m *Monitor) Run() {
	go func() {
		for {
			m.observeSTH()
			m.logger.Printf("Sleeping for %s before next STH check\n", m.sthFetchInterval)
			m.clk.Sleep(m.sthFetchInterval)
		}
	}()
	if m.certIssuerKey != nil {
		go func() {
			for {
				m.submitCertificate()
				m.logger.Printf("Sleeping for %s before next certificate submission\n",
					m.certSubmitInterval)
				m.clk.Sleep(m.certSubmitInterval)
			}
		}()
	}
}
