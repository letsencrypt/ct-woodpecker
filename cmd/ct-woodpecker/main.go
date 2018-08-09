package main

import (
	"flag"
	"log"
	"os"
	"path"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/cmd"
	"github.com/letsencrypt/ct-woodpecker/woodpecker"
)

var (
	clk    clock.Clock = clock.Default()
	stdout *log.Logger = log.New(
		os.Stdout,
		path.Base(os.Args[0])+" ",
		log.LstdFlags)
	stderr *log.Logger = log.New(
		os.Stderr,
		path.Base(os.Args[0])+" ",
		log.LstdFlags)
)

func main() {
	configFile := flag.String(
		"config",
		"test/config.json",
		"JSON ct-woodpekcer configuration file path")
	flag.Parse()

	// Load and validate the configuration from the provided JSON
	var conf woodpecker.Config
	if err := conf.Load(*configFile); err != nil {
		log.Fatalf("Unable to load ct-woodpecker config: %s", err)
	}

	// Create a Woodpecker with the provided monitoring configuration
	woodpecker, err := woodpecker.New(conf, stdout, stderr, clk)
	if err != nil {
		log.Fatalf("Unable to create ct-woodpecker: %s", err.Error())
	}

	// Start the monitoring process
	woodpecker.Run()

	// Block the main goroutine waiting for signals while the monitors run in
	// their own goroutines. WaitForSignal is provided a callback to cleanly
	// shutdown the metrics HTTP server when a signal is caught.
	cmd.WaitForSignal(stdout, func() { woodpecker.Stop() })
}
