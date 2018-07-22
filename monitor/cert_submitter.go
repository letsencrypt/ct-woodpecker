package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/letsencrypt/ct-woodpecker/storage"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// certSubmitterStats is a type to hold the prometheus metrics used by
// a certSubmitter
type certSubmitterStats struct {
	certSubmitLatency   *prometheus.HistogramVec
	certSubmitResults   *prometheus.CounterVec
	certStorageFailures *prometheus.CounterVec
}

var (
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
		}, []string{"uri", "precert"}),
		certSubmitResults: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_submit_results",
			Help: "Count of results from submitting certificate chains to CT logs, sliced by status",
		}, []string{"uri", "status", "precert"}),
		certStorageFailures: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_storage_failures",
			Help: "Count of failures to store submitted certificates and their SCTs",
		}, []string{"type"}),
	}
)

// SubmitterOptions is a struct holding options related to issuing and
// submitting certificates to the monitored log periodically.
type SubmitterOptions struct {
	// Interval describes the duration that the monitor will sleep between
	// submitting certificates to the monitored log.
	Interval time.Duration
	// Timeout describes the timeout used for submitting precerts/certs to the
	// monitored log.
	Timeout time.Duration
	// IssuerKey is the ECDSA private key used to sign issued certificates
	IssuerKey *ecdsa.PrivateKey
	// IssuerCert is the issuer certificate used to issue certificates submitted
	// to the monitored log. Its public key must correspond to the private key in
	// IssuerKey
	IssuerCert *x509.Certificate
	// SubmitPreCert controls whether or not precertificates are submitted
	SubmitPreCert bool
	// SubmitCert controls whether or not final certificates are submitted
	SubmitCert bool
}

// Valid checks that the SubmitterOptions has a valid positive interval and that
// the IssuerKey and IssuerCert are not nil.
func (o SubmitterOptions) Valid() error {
	if o.Interval <= 0 {
		return errors.New("Submitter interval must be > 0")
	}

	if o.Timeout <= 0 {
		return errors.New("Submitter timeout must be > 0")
	}

	if o.IssuerKey == nil {
		return errors.New("IssuerKey must not be nil")
	}

	if o.IssuerCert == nil {
		return errors.New("IssuerCert must not be nil")
	}

	return nil
}

// certSubmitter is a type for periodically issuing certificates and submitting
// them to a log's add-chain and add-pre-chain endpoints.
type certSubmitter struct {
	logger *log.Logger
	clk    clock.Clock
	client monitorCTClient
	logURI string
	logID  int64
	stats  *certSubmitterStats
	db     storage.Storage

	stopChannel chan bool

	// How long to sleep between submitting certificates to the log
	certSubmitInterval time.Duration
	// Timeout for precert/cert submissions to the log
	certSubmitTimeout time.Duration
	// ECDSA private key used to issue certificates to submit to the log.
	certIssuerKey *ecdsa.PrivateKey
	// Certificate used as the issuer for certificates submitted to the log.
	certIssuer *x509.Certificate
	// Should a precert be submitted?
	submitPreCert bool
	// Should a final cert be submitted?
	submitCert bool
}

// run starts a goroutine that calls submitCertificate, sleeps for
// certSubmitInterval and then repeats forever.
func (c *certSubmitter) run() {
	go func() {
		for {
			c.submitCertificates()
			c.logger.Printf("Sleeping for %s before next certificate submission\n",
				c.certSubmitInterval)
			select {
			case <-c.stopChannel:
				return
			case <-time.After(c.certSubmitInterval):
			}
		}
	}()
}

func (c *certSubmitter) stop() {
	c.logger.Printf("Stopping %s certSubmitter", c.logURI)
	c.stopChannel <- true
}

// submitCertificates issues a pre-certificate and a matching certificate with
// the certSubmitter's certIssuer/certIssuerKey. If `submitPreCert` is enabled
// then a precert is submitted. If `submitCert` is enabled then a final cert is
// submitted. All submissions are done on their own goroutine.
func (c *certSubmitter) submitCertificates() {
	// a certSubmitter requires a non-nil certIssuerKey and certIssuer. If somehow
	// was one created with nil values then panic.
	if c.certIssuerKey == nil || c.certIssuer == nil {
		panic("certSubmitter created with nil certIssuerKey or certIssuer\n")
	}

	certPair, err := pki.IssueTestCertificate(c.certIssuerKey, c.certIssuer, c.clk)
	if err != nil {
		// This should not occur and if it does we should abort hard
		panic(fmt.Sprintf("!!! Error issuing certificate: %s\n", err.Error()))
	}

	if c.submitPreCert {
		go c.submitCertificate(certPair.PreCert, true)
	}

	if c.submitCert {
		go c.submitCertificate(certPair.Cert, false)
	}
}

// submitCertificate submits a single x509 Certificate to a log. If `isPreCert`
// is true then the certificate is submitted via the log's add-pre-chain
// endpoint, otherwise the add-chain endpoint is used. The latency of the
// submission is tracked in the `cert_submit_latency` prometheus histogram. If
// the submission fails, or the returned SCT is invalid the
// `cert_submit_results` prometheus countervec is incremented with a "fail"
// status tag. If the submission succeeds the `cert_submit_results` prometheus
// countervec is incremented with a "ok" status tag. An SCT is considered
// invalid if the signature does not validate, or if the timestamp is too far in
// the future or the past (controlled by `requiredSCTFreshness`).
func (c certSubmitter) submitCertificate(cert *x509.Certificate, isPreCert bool) {
	chain := []ct.ASN1Cert{
		{Data: cert.Raw},
	}

	// Precert submissions also need the issuer in the chain because the SCT for
	// for precerts can contain the issuer SPKI.
	if isPreCert {
		chain = append(chain, ct.ASN1Cert{Data: c.certIssuer.Raw})
	}

	var submissionMethod func(context.Context, []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
	submissionMethod = c.client.AddChain
	certKind := "certificate"
	if isPreCert {
		submissionMethod = c.client.AddPreChain
		certKind = "precertificate"
	}
	c.logger.Printf("Submitting %s to %q\n", certKind, c.logURI)

	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(context.Background(), c.certSubmitTimeout)
	defer cancel()
	sct, err := submissionMethod(ctx, chain)
	elapsed := c.clk.Since(start)
	latencyLabels := prometheus.Labels{"uri": c.logURI, "precert": strconv.FormatBool(isPreCert)}
	c.stats.certSubmitLatency.With(latencyLabels).Observe(elapsed.Seconds())

	failLabels := prometheus.Labels{"uri": c.logURI, "status": "fail", "precert": strconv.FormatBool(isPreCert)}
	if err != nil {
		c.logger.Printf("!!! Error submitting %s to %q: %s\n", certKind, c.logURI, err.Error())
		c.stats.certSubmitResults.With(failLabels).Inc()
		return
	}

	if c.db != nil {
		sctBytes, err := cttls.Marshal(*sct)
		if err != nil {
			c.logger.Printf("!!! Error serializing SCT: %s", err)
			c.stats.certStorageFailures.WithLabelValues("marshalling").Inc()
			return
		}
		err = c.db.AddCert(c.logID, &storage.SubmittedCert{
			Cert:      cert.Raw,
			SCT:       sctBytes,
			Timestamp: sct.Timestamp,
		})
		if err != nil {
			c.logger.Printf("!!! Error saving submitted cert: %s", err)
			c.stats.certStorageFailures.WithLabelValues("storing").Inc()
			return
		}
	}

	ts := time.Unix(0, int64(sct.Timestamp)*int64(time.Millisecond))
	sctAge := c.clk.Since(ts)

	// Check that the SCT's timestamp is within an allowable tolerance into the
	// future and the past. The SCT's signature & log ID have already been verified by
	// `m.client.AddChain()`
	if sctAge > requiredSCTFreshness {
		c.logger.Printf("!!! Error submitting %s to %q: returned SCT timestamp signed %s in the future (expected <= %s)",
			certKind, c.logURI, sctAge, requiredSCTFreshness)
		c.stats.certSubmitResults.With(failLabels).Inc()
		return
	} else if -sctAge > requiredSCTFreshness {
		c.logger.Printf("!!! Error submitting %s to %q: returned SCT timestamp signed %s in the past (expected <= %s)",
			certKind, c.logURI, -sctAge, requiredSCTFreshness)
		c.stats.certSubmitResults.With(failLabels).Inc()
		return
	}

	successLabels := prometheus.Labels{"uri": c.logURI, "status": "ok", "precert": strconv.FormatBool(isPreCert)}
	c.stats.certSubmitResults.With(successLabels).Inc()
	c.logger.Printf("%s chain submitted to %q. SCT timestamp %s", certKind, c.logURI, ts)
}
