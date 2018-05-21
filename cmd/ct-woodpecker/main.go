package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/monitor"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	clk    clock.Clock = clock.Default()
	logger *log.Logger = log.New(
		os.Stdout,
		path.Base(os.Args[0])+" ",
		log.LstdFlags)
)

// failOnError aborts by calling log.Fatalf with the provided msg iff the err is
// not nil.
func failOnError(err error, msg string) {
	if err == nil {
		return
	}
	log.Fatalf("%s - %s", msg, err)
}

// config is a struct holding the command line configuration data
type config struct {
	STHFetchInterval string
	MetricsAddr      string
	Logs             []logConfig
}

// logConfig describes a log to be monitored
type logConfig struct {
	URI string
	Key string
}

// Valid checks that a logConfig is valid. If the log has no URI, an invalid
// URI, or no Key configured then an error is returned.
func (lc logConfig) Valid() error {
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
func (c *config) Valid() error {
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

// Load unmarhshals the JSON contents stored in the file path provided,
// populating the configuration object. An error is returned if the populated
// configuration is not valid.
func (c *config) Load(file string) error {
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

// catchSignals blocks forever waiting for SIGTERM, SIGINT or SIGHUP to arrive
// from the OS. When one of these signals occurs the provided callback is run
// and the program exits.
func catchSignals(callback func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)

	// Block waiting for a signal to arrive
	sig := <-sigChan
	logger.Printf("Caught %s signal\n", sig.String())
	callback()
	logger.Printf("Goodbye\n")
	os.Exit(0)
}

// initMetrics creates a HTTP server listening on the provided addr with
// a Prometheus handler registered for the /metrics URL path. The server is
// started on a dedicated Go routine before returning to the caller.
func initMetrics(addr string) *http.Server {
	// Create an HTTP server for Prometheus metrics to be served from.
	statsServer := &http.Server{
		Addr: addr,
	}
	http.Handle("/metrics", promhttp.Handler())
	logger.Printf("Handling /metrics on %s\n", addr)
	// Run the HTTP server in its own Go routine
	go func() {
		err := statsServer.ListenAndServe()
		if err != nil {
			log.Println(err.Error())
		}
	}()
	return statsServer
}

func main() {
	configFile := flag.String(
		"config",
		"test/config.json",
		"JSON ct-woodpekcer configuration file path")
	flag.Parse()

	// Load and validate the configuration from the provided JSON
	var conf config
	err := conf.Load(*configFile)
	failOnError(err, "Unable to load ct-woodpecker config")

	// Set up the Prometheus metrics HTTP server
	statsServer := initMetrics(conf.MetricsAddr)

	// Create and start monitors to do the work of monitoring the provided log
	fetchInterval, err := time.ParseDuration(conf.STHFetchInterval)
	failOnError(err, "Configured STH Fetch Interval is invalid")
	for _, log := range conf.Logs {
		m, err := monitor.New(
			log.URI,
			log.Key,
			fetchInterval,
			logger,
			clk)
		failOnError(err, fmt.Sprintf("Unable to create monitor for log %q", log.URI))
		m.Run()
	}

	// Block the main Go routine waiting for signals while the monitors run in
	// their own Go routines. catchSignals is provided a callback to cleanly
	// shutdown the metrics HTTP server when a signal is caught.
	catchSignals(func() {
		err := statsServer.Shutdown(context.Background())
		if err != nil {
			logger.Printf("Unable to shutdown statsServer cleanly: %s\n",
				err.Error())
		}
	})
}
