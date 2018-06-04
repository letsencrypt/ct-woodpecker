package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// certSubmitterStats is a type to hold the prometheus metrics used by
// a certSubmitter
type certSubmitterStats struct {
	certSubmitLatency *prometheus.HistogramVec
	certSubmitResults *prometheus.CounterVec
}

var (
	// submitTimeout controls how long each certificate chain submission should
	// wait before timing out
	submitTimeout = time.Second * 15
	// requiredSCTFreshness indicates how fresh a timestamp in a returned SCT must
	// be for it to be considered valid.
	requiredSCTFreshness = time.Minute * 10

	// certStats is a certSubmitterStats instance with promauto registered
	// prometheus metrics
	certStats *certSubmitterStats = &certSubmitterStats{
		certSubmitLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cert_submit_latency",
			Help:    "Latency submitting certificate chains to CT logs",
			Buckets: internetFacingBuckets,
		}, []string{"uri"}),
		certSubmitResults: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_submit_results",
			Help: "Count of results from submitting certificate chains to CT logs, sliced by status",
		}, []string{"uri", "status"}),
	}
)

// certSubmitter is a type for periodically issuing certificates and submitting
// them to a log's add-chain endpoint.
type certSubmitter struct {
	logger *log.Logger
	clk    clock.Clock
	client monitorCTClient
	logURI string
	stats  *certSubmitterStats

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

// run starts a goroutine that calls submitCertificate, sleeps for
// certSubmitInterval and then repeats forever.
func (c *certSubmitter) run() {
	go func() {
		for {
			c.submitCertificate()
			c.logger.Printf("Sleeping for %s before next certificate submission\n",
				c.certSubmitInterval)
			c.clk.Sleep(c.certSubmitInterval)
		}
	}()
}

// submitCertificate issues a certificate with the certSubmitter's
// certIssuer/certIssuerKey and submits it to a monitored log's add-chain
// endpoint. The latency of the submission is tracked in the
// `cert_submit_latency` prometheus histogram. If the submission fails, or the
// returned SCT is invalid the `cert_submit_results` prometheus countervec is
// incremented with a "fail" status tag. If the submission succeeds the
// `cert_submit_results` prometheus countervec is incremented with a "ok" status
// tag. An SCT is considered invalid if the signature does not validate, or if
// the timestamp is too far in the future or the past (controlled by
// `requiredSCTFreshness`).
func (c *certSubmitter) submitCertificate() {
	c.logger.Printf("Submitting certificate to %q\n", c.logURI)

	cert, err := pki.IssueTestCertificate(c.certIssuerKey, c.certIssuer, c.clk)
	if err != nil {
		// This should not occur and if it does we should abort hard
		panic(fmt.Sprintf("!!! Error issuing certificate: %s\n", err.Error()))
	}

	// Because ct-woodpecker issues directly off of a fake root the "chain" only
	// contains the leaf certificate we minted in issueCertificate()
	chain := []ct.ASN1Cert{
		ct.ASN1Cert{Data: cert.Raw},
	}

	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(context.Background(), submitTimeout)
	defer cancel()
	sct, err := c.client.AddChain(ctx, chain)
	elapsed := c.clk.Since(start)
	latencyLabels := prometheus.Labels{"uri": c.logURI}
	c.stats.certSubmitLatency.With(latencyLabels).Observe(elapsed.Seconds())

	failLabels := prometheus.Labels{"uri": c.logURI, "status": "fail"}
	if err != nil {
		c.logger.Printf("!!! Error submitting certificate to %q: %s\n", c.logURI, err.Error())
		c.stats.certSubmitResults.With(failLabels).Inc()
		return
	}

	ts := time.Unix(0, int64(sct.Timestamp)*int64(time.Millisecond))
	sctAge := c.clk.Since(ts)

	// Check that the SCT's timestamp is within an allowable tolerance into the
	// future and the past. The SCT's signature & log ID have already been verified by
	// `m.client.AddChain()`
	if sctAge > requiredSCTFreshness {
		c.logger.Printf("!!! Error submitting certificate to %q: returned SCT timestamp signed %s in the future (expected <= %s)",
			c.logURI, sctAge, requiredSCTFreshness)
		c.stats.certSubmitResults.With(failLabels).Inc()
		return
	} else if -sctAge > requiredSCTFreshness {
		c.logger.Printf("!!! Error submitting certificate to %q: returned SCT timestamp signed %s in the past (expected <= %s)",
			c.logURI, -sctAge, requiredSCTFreshness)
		c.stats.certSubmitResults.With(failLabels).Inc()
		return
	}

	successLabels := prometheus.Labels{"uri": c.logURI, "status": "ok"}
	c.stats.certSubmitResults.With(successLabels).Inc()
	c.logger.Printf("Certificate chain submitted to %q. SCT timestamp %s", c.logURI, ts)
}
