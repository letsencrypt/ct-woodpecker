package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// WaitForSignal blocks forever waiting for SIGTERM, SIGINT or SIGHUP to arrive
// from the OS. When one of these signals occurs the provided callback is run
// and the program exits. The provider logger is used to print which signal was
// caught and a polite goodbye.
func WaitForSignal(logger *log.Logger, callback func()) {
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
