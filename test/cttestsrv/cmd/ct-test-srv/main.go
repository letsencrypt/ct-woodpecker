// This is a test server that implements the subset of RFC6962 APIs needed by
// ct-woodpecker.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/letsencrypt/ct-woodpecker/cmd"
	"github.com/letsencrypt/ct-woodpecker/test/cttestsrv"
)

// config is a struct for holding multiple cttestserv.Personalities that will be
// created and started in `main`
type config struct {
	Personalities []cttestsrv.Personality
}

// valid checks that a configuration is acceptable. If there is a problem an
// error is returned, otherwise nil is returned.
func (c config) valid() error {
	if len(c.Personalities) < 1 {
		return errors.New(
			"Configuration must specify at least one CT test server personality")
	}
	return nil
}

// main runs a number of CT test server personalities and then blocks waiting
// for signals.
func main() {
	logger := log.New(
		os.Stdout,
		path.Base(os.Args[0])+" ",
		log.LstdFlags)

	// Load the configuration specified on the command line
	configFile := flag.String("config", "", "Path to config file.")
	flag.Parse()
	if *configFile == "" {
		logger.Fatal("You must specify a -config file")
	}
	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		logger.Fatal(err)
	}
	var c config
	err = json.Unmarshal(data, &c)
	if err != nil {
		logger.Fatal(err)
	}
	if err := c.valid(); err != nil {
		logger.Fatalf("%s: %s", *configFile, err.Error())
	}

	// Create and start an IntegrationSrv for each of the configured personalities
	var servers []*cttestsrv.IntegrationSrv
	for _, p := range c.Personalities {
		srv, err := cttestsrv.NewServer(p, logger)
		if err != nil {
			logger.Fatal(err)
		}
		servers = append(servers, srv)
		srv.Run()
	}

	// Block for signals. When a signal is received shutdown all of the
	// IntegrationSrv instances that were started.
	cmd.WaitForSignal(logger, func() {
		for _, srv := range servers {
			srv.Shutdown()
		}
	})
}
