package woodpecker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/monitor"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config is a struct holding the command line configuration data
type Config struct {
	STHFetchInterval string
	MetricsAddr      string
	Logs             []LogConfig
}

// LogConfig describes a log to be monitored
type LogConfig struct {
	URI string
	Key string
}

// Valid checks that a logConfig is valid. If the log has no URI, an invalid
// URI, or no Key configured then an error is returned.
func (lc LogConfig) Valid() error {
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
	return nil
}

// Valid checks that a config is valid. If the STHFetchInterval is invalid,
// or there are no logs configured, or a configured log is invalid, then an
// error is returned. If no MetricsAddr is provided the default will be
// populated.
func (c *Config) Valid() error {
	if _, err := time.ParseDuration(c.STHFetchInterval); err != nil {
		return err
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":1971"
	}
	if len(c.Logs) < 1 {
		return errors.New("At least one log must be configured")
	}
	for _, lc := range c.Logs {
		if err := lc.Valid(); err != nil {
			return err
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

// Woodpecker is a struct collecting up the things required to expose metrics
// gathered from running monitors.
type Woodpecker struct {
	logger        *log.Logger
	clk           clock.Clock
	monitors      []*monitor.Monitor
	metricsServer *http.Server
}

// New creates a Woodpecker from the provided configuration, logger and clock.
// If the configuration is invalid or an error occurs initializing the
// woodpecker it is returned. The returned Woodpecker and its monitors are not
// started until the Start() function is called.
func New(c Config, logger *log.Logger, clk clock.Clock) (*Woodpecker, error) {
	// Check the configuration is valid
	if err := c.Valid(); err != nil {
		return nil, err
	}

	// Create and start monitors to do the work of monitoring the provided log
	fetchInterval, err := time.ParseDuration(c.STHFetchInterval)
	if err != nil {
		return nil, err
	}
	var monitors []*monitor.Monitor
	for _, logConf := range c.Logs {
		m, err := monitor.New(
			logConf.URI,
			logConf.Key,
			fetchInterval,
			logger,
			clk)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, m)
	}

	return &Woodpecker{
		logger:        logger,
		monitors:      monitors,
		metricsServer: initMetrics(c.MetricsAddr),
	}, nil
}

// initMetrics creates a HTTP server listening on the provided addr with
// a Prometheus handler registered for the /metrics URL path. The server is
// started on a dedicated goroutine before returning to the caller.
func initMetrics(addr string) *http.Server {
	// Create an HTTP server for Prometheus metrics to be served from.
	statsServer := &http.Server{
		Addr: addr,
	}
	http.Handle("/metrics", promhttp.Handler())
	return statsServer
}

// Run starts each of the Woodpecker's monitors
func (w *Woodpecker) Run() {
	// Run the metrics HTTP server in its own goroutine
	go func() {
		err := w.metricsServer.ListenAndServe()
		if err != nil {
			w.logger.Println(err.Error())
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
}
