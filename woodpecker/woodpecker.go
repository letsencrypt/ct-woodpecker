// Package woodpecker provides a high level monitoring process responsible for
// monitoring one or more CT logs. Its primary use case is to be created and
// used from the context of a command line tool and so it accepts options that
// are relatively unprocessed (e.g. paths to certificate files, raw duration
// strings). Individual `monitor` objects are created for each of the logs to be
// monitored. See the `monitor` package for more information on the monitoring
// process.
package woodpecker

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/pprof"
	"net/url"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/monitor"
	"github.com/letsencrypt/ct-woodpecker/pki"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// STHFetchConfig describes the configuration for fetching log STHs
// periodically.
type STHFetchConfig struct {
	// Interval is a duration string describing the sleep period between STH fetches
	Interval string
	// Timeout is a duration string describing the timeout for STH fetches
	Timeout string
}

// CertSubmitConfig describes the configuration for submitting certificates to
// a log periodically.
type CertSubmitConfig struct {
	// CertIssuerKeyPath is a path to a file containing a BASE64 encoded ECDSA
	// private key
	// Generate with `ct-woodpecker-genissuer` from `test/`
	CertIssuerKeyPath string

	// CertIssuerPath is a path to a file containing a PEM encoded issuer
	// certificate with a public key matching the private key in CertIssuerKey
	// Generate with `ct-woodpecker-genissuer` from `test/`
	CertIssuerPath string

	// Interval is a duration string describing the sleep period between
	// submitting certificates to the monitor logs
	Interval string
	// Timeout is a duration string describing the timeout for precert/cert
	// submissions
	Timeout string
}

// InclusionCheckerConfig describes the configuration for checking submitted
// certificates have been included in a monitored log periodically.
type InclusionCheckerConfig struct {
	// How frequently to check the log for new entries (e.g. 2s, 1m)
	Interval string
	// The maximum number of entries to consider each Interval.
	// The rate Interval / MaxGetEntries governs how many entries the inclusion
	// checker can process per second, and it should be significantly higher than
	// the expected growth rate of the log.
	MaxGetEntries int64
}

// Config is a struct holding woodpecker configuration. A woodpecker can be
// configured to fetch monitored log STHs or submit certificates periodically to
// the monitored logs, or both.
type Config struct {
	// Address for the woodpecker metrics server
	MetricsAddr string

	// URI for database storage
	DBURI string

	// File to read a password from for database.
	DBPasswordFile string

	// Configuration for STH fetching (nil if no fetching is to be done)
	FetchConfig *STHFetchConfig

	// Configuration for certificate submission (nil if no submission is to be done)
	SubmitConfig *CertSubmitConfig

	// Configuration for checking certificate inclusion (nil if no certificate
	// inclusion checking is to be done)
	InclusionConfig *InclusionCheckerConfig

	// Slice of logConfigs describing logs to monitor
	Logs []LogConfig
}

// LogConfig describes a log to be monitored
type LogConfig struct {
	// URI of the CT Log
	URI string
	// Base64 encoded public key for the CT log
	Key string
	// TreeSize to start at when checking for inclusion
	Start int64
	// Should woodpecker submit certificates to this log every CertSubmitInterval?
	SubmitCert bool
	// Should woodpecker submit pre-certificates to this log every CertSubmitInterval?
	SubmitPreCert bool
	// For a temporal log shard, the WindowStart is the certificate NotBefore
	// cutoff. If set and this log's SubmitCert or SubmitPreCert is true any
	// CertSubmitConfigs will generate a certificate with a validity period
	// starting after this datestamp.
	WindowStart string
	// For a temporal log shard, the WindowEnd is the certificate NotAfter cutoff.
	// If set and this log's SubmitCert or SubmitPreCert is true any
	// CertSubmitConfigs will generate a certificate with a validity period ending
	// before this datestamp.
	WindowEnd string
}

// Valid checks that a logConfig is valid. If the log has no URI, an invalid
// URI, or no Key configured then an error is returned.
func (lc *LogConfig) Valid() error {
	if lc.URI == "" {
		return errors.New("log URI must not be empty")
	}
	if url, err := url.Parse(lc.URI); err != nil {
		return fmt.Errorf("log URI %q is invalid: %s", lc.URI, err.Error())
	} else if url.Scheme != "http" && url.Scheme != "https" {
		return fmt.Errorf("log URI %q is invalid: protocol scheme must be http:// or https://", lc.URI)
	}
	if lc.Key == "" {
		return errors.New("log Key must not be empty")
	}
	// If there is a start treesize set, it must be >= 0
	if lc.Start < 0 {
		return errors.New("log start must be > 0 if set")
	}
	// If there is a WindowStart it must be a valid timestamp
	if lc.WindowStart != "" {
		if _, err := time.Parse(time.RFC3339, lc.WindowStart); err != nil {
			return errors.New("WindowStart is invalid")
		}
	}
	// If there is a WindowEnd it must be a valid timestamp
	if lc.WindowEnd != "" {
		if _, err := time.Parse(time.RFC3339, lc.WindowEnd); err != nil {
			return errors.New("WindowEnd is invalid")
		}
	}
	return nil
}

// Valid checks that a woodpecker config is valid. At least one log must be
// configured. One of FetchConfig or SubmitConfig must be configured. If there
// are logs with SubmitCert/SubmitPreCert then there must be a SubmitConfig.
// Conversely, if there are no logs with SubmitCert/SubmitPreCert but there is
// a SubmitConfig it is considered an error. All duration strings must parse as
// valid time.Duration instances. If no MetricsAddr is provided the default will
// be populated.
func (c *Config) Valid() error {
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":1971"
	}
	if len(c.Logs) < 1 {
		return errors.New("At least one log must be configured")
	}

	if c.FetchConfig == nil && c.SubmitConfig == nil {
		return errors.New("One of FetchConfig or SubmitConfig must not be nil")
	}

	if c.SubmitConfig == nil && c.InclusionConfig != nil {
		return errors.New("InclusionConfig can not be nil if SubmitConfig is nil")
	}

	if c.FetchConfig != nil {
		if _, err := time.ParseDuration(c.FetchConfig.Interval); err != nil {
			return err
		}
	}

	if c.InclusionConfig != nil {
		if _, err := time.ParseDuration(c.InclusionConfig.Interval); err != nil {
			return err
		}
	}

	var submit bool
	for _, lc := range c.Logs {
		if err := lc.Valid(); err != nil {
			return err
		}
		// Note that there is at least one log configured to have certificates
		// submitted
		if lc.SubmitCert || lc.SubmitPreCert {
			submit = true
		}
	}

	// If there is a log configured to have certificates submitted to it then the
	// configuration must have a valid cert submit interval and a non-empty
	// CertIssuerKeyPath and CertIssuerPath
	if submit && c.SubmitConfig == nil {
		return errors.New("SubmitConfig must not be nil when one or more logs has SubmitCert or SubmitPreCert set to true")
	}
	if !submit && c.SubmitConfig != nil {
		return errors.New("SubmitConfig was not nil but no logs had SubmitCert or SubmitPreCert set to true")
	}
	if submit && c.SubmitConfig != nil {
		if _, err := time.ParseDuration(c.SubmitConfig.Interval); err != nil {
			return err
		}
		if c.SubmitConfig.CertIssuerKeyPath == "" {
			return errors.New("CertIssuerKeyPath can not be empty")
		}
		if c.SubmitConfig.CertIssuerPath == "" {
			return errors.New("CertIssuerPath can not be empty")
		}
	}

	return nil
}

// Load unmarshals the JSON contents stored in the file path provided,
// populating the configuration object. An error is returned if the populated
// configuration is not valid.
func (c *Config) Load(file string) error {
	if file == "" {
		return errors.New("Config file path must not be empty")
	}

	configBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(configBytes, c)
	if err != nil {
		return err
	}

	return c.Valid()
}

// Woodpecker is a struct responsible for monitoring one or more CT logs. There
// is one `monitor.Monitor` for each monitored logs.
type Woodpecker struct {
	logger        *log.Logger
	monitors      []*monitor.Monitor
	metricsServer *http.Server
}

// New creates a Woodpecker from the provided configuration, stdout logger,
// stderr logger and clock.
// If the configuration is invalid or an error occurs initializing the
// woodpecker it is returned. The returned Woodpecker and its monitors are not
// started until the Start() function is called.
func New(c Config, stdout, stderr *log.Logger, clk clock.Clock) (*Woodpecker, error) {
	if err := c.Valid(); err != nil {
		return nil, err
	}

	var err error
	var fetchInterval time.Duration
	var fetchTimeout time.Duration
	if c.FetchConfig != nil {
		fetchInterval, err = time.ParseDuration(c.FetchConfig.Interval)
		if err != nil {
			return nil, err
		}
		fetchTimeout, err = time.ParseDuration(c.FetchConfig.Timeout)
		if err != nil {
			return nil, err
		}
	}

	var certInterval time.Duration
	var certTimeout time.Duration
	var issuerCert *x509.Certificate
	var issuerKey *ecdsa.PrivateKey
	if c.SubmitConfig != nil {
		certInterval, err = time.ParseDuration(c.SubmitConfig.Interval)
		if err != nil {
			return nil, err
		}
		certTimeout, err = time.ParseDuration(c.SubmitConfig.Timeout)
		if err != nil {
			return nil, err
		}
		cert, err := pki.LoadCertificate(c.SubmitConfig.CertIssuerPath)
		if err != nil {
			return nil, err
		}
		issuerCert = cert
		key, err := pki.LoadPrivateKey(c.SubmitConfig.CertIssuerKeyPath)
		if err != nil {
			return nil, err
		}
		issuerKey = key
	}

	var inclusionInterval time.Duration
	if c.InclusionConfig != nil {
		inclusionInterval, err = time.ParseDuration(c.InclusionConfig.Interval)
		if err != nil {
			return nil, err
		}
	}

	var monitors []*monitor.Monitor
	for _, logConf := range c.Logs {
		opts := monitor.Options{
			LogURI:         logConf.URI,
			LogKey:         logConf.Key,
			DBURI:          c.DBURI,
			DBPasswordFile: c.DBPasswordFile,
		}
		if c.FetchConfig != nil {
			opts.FetchOpts = &monitor.FetcherOptions{
				Interval: fetchInterval,
				Timeout:  fetchTimeout,
			}
		}
		if c.SubmitConfig != nil {
			var windowStart *time.Time
			if logConf.WindowStart != "" {
				start, _ := time.Parse(time.RFC3339, logConf.WindowStart)
				windowStart = &start
			}
			var windowEnd *time.Time
			if logConf.WindowEnd != "" {
				end, _ := time.Parse(time.RFC3339, logConf.WindowEnd)
				windowEnd = &end
			}
			opts.SubmitOpts = &monitor.SubmitterOptions{
				Interval:      certInterval,
				Timeout:       certTimeout,
				IssuerCert:    issuerCert,
				IssuerKey:     issuerKey,
				SubmitPreCert: logConf.SubmitPreCert,
				SubmitCert:    logConf.SubmitCert,
				WindowStart:   windowStart,
				WindowEnd:     windowEnd,
			}
		}
		if c.InclusionConfig != nil {
			opts.InclusionOpts = &monitor.InclusionOptions{
				Interval:      inclusionInterval,
				MaxGetEntries: c.InclusionConfig.MaxGetEntries,
				StartIndex:    logConf.Start,
			}
		}
		m, err := monitor.New(opts, stdout, stderr, clk)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, m)
	}

	return &Woodpecker{
		logger:        stdout,
		monitors:      monitors,
		metricsServer: initMetrics(c.MetricsAddr, stderr),
	}, nil
}

// initMetrics creates a HTTP server listening on the provided addr with
// a Prometheus handler registered under the /metrics URL path and pprof
// handlers under the /debug/pprof path.
//
// The returned server is not started. The caller must call ListenAndServe
// itself.
func initMetrics(addr string, stderr *log.Logger) *http.Server {
	mux := http.NewServeMux()

	// Register the available pprof handlers on a mux that can be shared with
	// prometheus.
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	// These handlers are defined in runtime/pprof instead of net/http/pprof, and
	// have to be accessed through net/http/pprof's Handler func.
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	// Handle prometheus metrics under the /metrics path using the default
	// gatherer. All of ct-woodpecker's promauto stats will be registered with
	// this gatherer.
	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Write errors serving metrics to the stderr Logger instance.
			ErrorLog: stderr,
		}))

	// Use the mux for the returned http server.
	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}

// Run starts each of the Woodpecker's monitors
func (w *Woodpecker) Run() {
	// Run the metrics HTTP server in its own goroutine
	go func() {
		err := w.metricsServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			w.logger.Fatalf("metrics server failed: %s", err)
		}
	}()

	// Run each of the Woodpecker's monitors
	for _, m := range w.monitors {
		m.Run()
	}
}

// Stop stops each of the Woodpecker's monitors
func (w *Woodpecker) Stop() {
	err := w.metricsServer.Shutdown(context.Background())
	if err != nil {
		w.logger.Printf("Unable to shutdown statsServer cleanly: %s\n",
			err.Error())
	}
	for _, m := range w.monitors {
		m.Stop()
	}
}
