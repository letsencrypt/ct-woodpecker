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
)

// internetFacingBuckets are histogram buckets suitable for measuring
// latencies that involve traversing the public internet.
var internetFacingBuckets = []float64{.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45}

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

	fetcher   *sthFetcher
	submitter *certSubmitter
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

	m := &Monitor{
		logger: logger,
		clk:    clk,

		fetcher: &sthFetcher{
			logger:           logger,
			clk:              clk,
			stats:            sthStats,
			client:           client,
			logURI:           uri,
			sthFetchInterval: sthFetchInterval,
		},
	}

	if certIssuerKey != nil {
		m.submitter = &certSubmitter{
			logger:             logger,
			clk:                clk,
			stats:              certStats,
			client:             client,
			logURI:             uri,
			certSubmitInterval: certSubmitInterval,
			certIssuer:         certIssuer,
			certIssuerKey:      certIssuerKey,
		}
	}

	return m, nil
}

// Run starts the log monitoring process by starting the log's STH fetcher and
// the cert submitter.
func (m *Monitor) Run() {
	m.fetcher.run()

	if m.submitter != nil {
		m.submitter.run()
	}
}
