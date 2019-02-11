// Package monitor provides the mechanisms used to monitor a single CT log. This
// includes fetching the log STH periodically as well as issuing certificates
// and submitting them to the log periodically.
package monitor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctClient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/storage"
)

// defaultMaximumMergeDelay is the MMD (expressed in seconds) used if the
// monitored log does not have an explicit MMD from configuration
const defaultMaximumMergeDelay = 86400

// internetFacingBuckets are histogram buckets suitable for measuring
// latencies that involve traversing the public internet.
var internetFacingBuckets = []float64{.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45}

// monitorCTClient is an interface that specifies the ctClient.LogClient
// functions that the monitor package uses. This interface allows for easy
// shimming of client methods with mock implementations for unit testing.
type monitorCTClient interface {
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	AddChain(context.Context, []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
	AddPreChain(context.Context, []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
	GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error)
	GetSTHConsistency(context.Context, uint64, uint64) ([][]byte, error)
}

// MonitorOptions is a struct for holding monitor configuration options
type MonitorOptions struct {
	// LogURI is the URI of the log to be monitored
	LogURI string
	// LogKey is the BASE64 encoded DER of the log's public key (No PEM header/footer).
	LogKey string
	// MaximumMergeDelay is the fixed amount of time (expressed in seconds) that
	// the log commits to incorporating a certificate within after returning an
	// SCT.
	MaximumMergeDelay int

	DBURI string

	// FetchOpts holds the FetcherOptions for fetching the log STH periodically.
	// It may be nil if no STH fetching is to be performed.
	FetchOpts *FetcherOptions
	// SubmitOpts holds the optional SubmitterOptions for submitting certificates
	// to the log periodically. It may be nil if no certificate submission is to
	// be performed.
	SubmitOpts *SubmitterOptions
	// InclusionOpts holds the optional InclusionOptions for checking submitted
	// certificates for inclusion in the log. It may be nil if no certificate
	// inclusion checks are to be performed.
	InclusionOpts *InclusionOptions
}

// Valid enforces that a MonitorOptions instance is valid. There must be
// a non-empty LogURI and LogKey. One of FetchOpts or SubmitOpts must not be
// non-nil and valid.
func (conf MonitorOptions) Valid() error {
	if conf.LogURI == "" {
		return errors.New("LogURI must not be empty")
	}

	if conf.LogKey == "" {
		return errors.New("LogKey must not be empty")
	}

	if conf.MaximumMergeDelay < 0 {
		return errors.New("MaximumMergeDelay must be >= 0")
	}

	if conf.FetchOpts == nil && conf.SubmitOpts == nil {
		return errors.New("One of FetchOpts or SubmitOpts must not be nil")
	}

	if conf.FetchOpts != nil {
		if err := conf.FetchOpts.Valid(); err != nil {
			return err
		}
	}

	if conf.SubmitOpts != nil {
		if err := conf.SubmitOpts.Valid(); err != nil {
			return err
		}
	}

	return nil
}

// Monitor is a struct for monitoring a CT log. It may fetch the log's STH
// periodically or submit certs periodically or both depending on whether
// fetcher and submitter are not nil.
type Monitor struct {
	stdout *log.Logger
	stderr *log.Logger
	clk    clock.Clock

	fetcher          *sthFetcher
	submitter        *certSubmitter
	inclusionChecker *inclusionChecker
}

// New creates a Monitor for the given options. The monitor will not be started
// until Run() is called.
func New(opts MonitorOptions, stdout, stderr *log.Logger, clk clock.Clock) (*Monitor, error) {
	if err := opts.Valid(); err != nil {
		return nil, err
	}

	hc := &http.Client{
		Timeout: time.Minute,
	}

	// By convention CT log public keys are shared/configured in base64 encoded
	// DER. The `ctclient.New()` constructor expects a vanilla PEM block, that is,
	// base64 encoded DER surrounded by a header/footer. We manufacture such
	// a block here using the b64key
	pubkey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
		opts.LogKey)

	// Create a CT client for the log. We pass a PublicKey in the
	// `jsonclient.Options` to ensure that the STH signature will be validated
	// when we call the client's `GetSTH` function. If this parameter is nil no
	// signature check is performed.
	client, err := ctClient.New(opts.LogURI, hc, jsonclient.Options{
		Logger:    stdout,
		PublicKey: pubkey,
	})
	if err != nil {
		return nil, err
	}

	var db storage.Storage
	if opts.DBURI != "" {
		db, err = storage.New("mysql", opts.DBURI)
		if err != nil {
			return nil, err
		}
	}

	m := &Monitor{
		stdout: stdout,
		stderr: stderr,
		clk:    clk,
	}

	keyHash := sha256.Sum256([]byte(opts.LogKey))
	logID := big.NewInt(0).SetBytes(keyHash[:]).Int64()

	mmd := defaultMaximumMergeDelay
	if opts.MaximumMergeDelay > 0 {
		mmd = opts.MaximumMergeDelay
	}

	// All of the monitor's monitorChecks share these base properties
	mc := monitorCheck{
		logURI:            opts.LogURI,
		logID:             logID,
		maximumMergeDelay: mmd,
		clk:               clk,
		stdout:            stdout,
		stderr:            stderr,
	}

	if opts.FetchOpts != nil {
		// Copy the base MC and set the label
		fetcherMC := mc
		fetcherMC.label = "sthFetcher"
		m.fetcher = newSTHFetcher(fetcherMC, opts.FetchOpts, client)
	}

	if opts.SubmitOpts != nil {
		submitterMC := mc
		submitterMC.label = "certSubmitter"
		m.submitter = newCertSubmitter(submitterMC, opts.SubmitOpts, client, db)
	}

	if opts.InclusionOpts != nil {
		inclusionMC := mc
		inclusionMC.label = "inclusionChecker"
		ic, err := newInclusionChecker(
			inclusionMC,
			opts.InclusionOpts,
			client,
			opts.LogKey,
			db)
		if err != nil {
			return nil, err
		}
		m.inclusionChecker = ic
	}

	return m, nil
}

// STHFetcher returns true if the monitor is configured to fetch the monitor
// log's STH periodically.
func (m *Monitor) STHFetcher() bool {
	return m.fetcher != nil
}

// CertSubmitter returns true if the monitor is configured to submit
// certificates or precertificates to the monitored log periodically.
func (m *Monitor) CertSubmitter() bool {
	return m.submitter != nil
}

// Run starts the log monitoring process by starting the log's STH fetcher,
// the cert submitter, and the inclusion checker.
func (m *Monitor) Run() {
	if m.fetcher != nil {
		m.fetcher.run()
	}

	if m.submitter != nil {
		m.submitter.run()
	}

	if m.inclusionChecker != nil {
		m.inclusionChecker.run()
	}
}

func (m *Monitor) Stop() {
	if m.fetcher != nil {
		m.fetcher.stop()
	}

	if m.submitter != nil {
		m.submitter.stop()
	}

	if m.inclusionChecker != nil {
		m.inclusionChecker.stop()
	}
}
