package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// sthFetchStats is a type to hold the prometheus metrics used by
// a sthFetcher
type sthFetchStats struct {
	sthTimestamp       *prometheus.GaugeVec
	sthAge             *prometheus.GaugeVec
	sthFailures        *prometheus.CounterVec
	sthLatency         *prometheus.HistogramVec
	sthProofLatency    *prometheus.HistogramVec
	sthInconsistencies *prometheus.CounterVec
}

// sthStats is a sthFetchStats instance with promauto registered
// prometheus metrics
var sthStats *sthFetchStats = &sthFetchStats{
	sthTimestamp: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sth_timestamp",
		Help: "Timestamp of observed CT log signed tree head (STH)",
	}, []string{"uri"}),
	sthAge: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sth_age",
		Help: "Elapsed time since observed CT log signed tree head (STH) timestamp",
	}, []string{"uri"}),
	sthFailures: promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sth_failures",
		Help: "Count of failures fetching CT log signed tree head (STH)",
	}, []string{"uri"}),
	sthLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sth_latency",
		Help:    "Latency observing CT log signed tree head (STH)",
		Buckets: internetFacingBuckets,
	}, []string{"uri"}),
	sthProofLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sth_proof_latency",
		Help:    "Latency requesting CT signed tree head (STH) consistency proof",
		Buckets: internetFacingBuckets,
	}, []string{"uri"}),
	sthInconsistencies: promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sth_inconsistencies",
		Help: "Count of times two CT log signed tree heads (STHs) could not be proved consistent",
	}, []string{"uri", "type"}),
}

// FetcherOptions is a struct holding options for STH fetching.
type FetcherOptions struct {
	// Interval describes the duration that the monitor will sleep between
	// fetching the STH.
	Interval time.Duration
	// Timeout is the STH fetch timeout.
	Timeout time.Duration
}

// Valid checks that the FetcherOptions interval is positive.
func (o FetcherOptions) Valid() error {
	if o.Interval <= 0 {
		return errors.New("Fetcher interval must be >= 0")
	}
	if o.Timeout <= 0 {
		return errors.New("Fetcher timeout must be >= 0")
	}
	return nil
}

// sthFetcherVerifier is an interface that specifies the merkle.LogVerifier
// functions that the sthFetcher uses. This interface allows for easy
// shimming of client methods with mock implementations for unit testing.
type sthFetcherVerifier interface {
	VerifyConsistencyProof(int64, int64, []byte, []byte, [][]byte) error
}

// sthFetcher is a type for periodically fetching a log's STH and publishing
// metrics about it.
type sthFetcher struct {
	logger *log.Logger
	clk    clock.Clock
	client monitorCTClient
	logURI string
	stats  *sthFetchStats

	stopChannel chan bool

	// How long to sleep between fetching the log's current STH
	sthFetchInterval time.Duration
	// How long to wait before giving up on an STH fetch or an STH consistency
	// proof.
	sthTimeout time.Duration

	// prevSTH is the last STH that was fetched from the log
	prevSTH *ct.SignedTreeHead

	// prevSTHMu is a Mutex for controlling updates to prevSTH
	prevSTHMu sync.Mutex

	// verifier is used by verifySTHConsistency to prove consistency between two
	// STHs
	verifier sthFetcherVerifier
}

// newSTHFetcher returns an sthFetcher instance populated based on the provided
// arguments
func newSTHFetcher(
	logger *log.Logger,
	clk clock.Clock,
	client monitorCTClient,
	logURI string,
	sthFetchInterval time.Duration,
	sthTimeout time.Duration) *sthFetcher {
	return &sthFetcher{
		logger:           logger,
		clk:              clk,
		client:           client,
		logURI:           logURI,
		sthFetchInterval: sthFetchInterval,
		sthTimeout:       sthTimeout,

		stats:       sthStats,
		stopChannel: make(chan bool),
		verifier:    merkle.NewLogVerifier(rfc6962.DefaultHasher),
	}
}

// logErrorf formats a message to the sthFetcher's logger prefixed to identify
// that an error occurred, that it was an sth-fetcher, and the logURI the error
// affects
func (f *sthFetcher) logErrorf(format string, args ...interface{}) {
	// TODO(@cpu): We should be using os.Stderr here but doing so will mean
	// changing integration tests. See
	// https://github.com/letsencrypt/ct-woodpecker/issues/36
	line := fmt.Sprintf(format, args...)
	f.logger.Print("[ERROR]", "sth-fetcher", f.logURI, ":", line)
}

// logf formats a message to write to the sthFetcher's logger prefixed to
// identify the source as an sth-fetcher for a specific logURI
func (f *sthFetcher) logf(format string, args ...interface{}) {
	f.logger.Printf(fmt.Sprintf("sth-fetcher %s : %s\n", f.logURI, format), args...)
}

// log writes a message to the sthFetcher's logger prefixed to identify the
// source as an sth-fetcher for a specific logURI. For format string usage see
// logf.
func (f *sthFetcher) log(msg string) {
	f.logger.Printf("sth-fetcher %s : %s\n", f.logURI, msg)
}

// Run starts the log STH fetching process by creating a goroutine that will loop
// forever fetching the log's STH in a goroutine and then sleeping.
func (f *sthFetcher) run() {
	go func() {
		for {
			go f.observeSTH()
			f.logf("Sleeping for %s before next STH check\n", f.sthFetchInterval)
			select {
			case <-f.stopChannel:
				return
			case <-time.After(f.sthFetchInterval):
			}
		}
	}()
}

func (f *sthFetcher) stop() {
	f.log("Stopping")
	f.stopChannel <- true
}

// observeSTH fetches a monitored log's signed tree head (STH). The latency of
// this operation is published to the `sth_latency` metric. The clocktime elapsed
// since the STH's timestamp is published to the `sth_age` metric. If an error
// occurs the `sth_failures` metric will be incremented. If the operation
// succeeds then the `sth_timestamp` gauge will be updated to the returned STH's
// timestamp. The newly observerd STH will be stored as `f.prevSTH`. If
// `f.prevSTH` is not nil, then `observeSTH` will asynchronously validate
// consistency between `f.prevSTH` and the newly observed STH.
func (f *sthFetcher) observeSTH() {
	labels := prometheus.Labels{"uri": f.logURI}
	f.log("Fetching STH")

	start := f.clk.Now()
	ctx, cancel := context.WithTimeout(context.Background(), f.sthTimeout)
	defer cancel()
	newSTH, err := f.client.GetSTH(ctx)
	elapsed := f.clk.Since(start)
	f.stats.sthLatency.With(labels).Observe(elapsed.Seconds())

	if err != nil {
		f.logErrorf("failed to fetch STH: %q : %#v", err.Error(), err)
		f.stats.sthFailures.With(labels).Inc()
		return
	}

	f.stats.sthTimestamp.With(labels).Set(float64(newSTH.Timestamp))
	ts := time.Unix(0, int64(newSTH.Timestamp)*int64(time.Millisecond))
	sthAge := f.clk.Since(ts)
	f.stats.sthAge.With(labels).Set(sthAge.Seconds())

	f.logf("STH verified. Timestamp: %s Age: %s TreeSize: %d Root Hash: %x",
		ts, sthAge, newSTH.TreeSize, newSTH.SHA256RootHash)

	f.prevSTHMu.Lock()
	defer f.prevSTHMu.Unlock()

	if f.prevSTH != nil {
		go f.verifySTHConsistency(f.prevSTH, newSTH)
	}
	f.prevSTH = newSTH
}

// verifySTHConsistency fetches and validates a consistency proof between
// firstSTH and secondSTH. If the two STHs don't verify then the
// `sth_inconsistencies` prometheus counter is incremented with a label
// indicating the category of inconsistency and an error is logged with
// `logErrorf`. Presently there are three possible categories of STH consistency
// failure:
// 1. "equal-treesize-inequal-hash" - the two STHs are the same tree size but
//    have different root hashes.
// 2. "failed-to-get-proof" - the monitor encountered an error getting
//    a consistency proof between the two STHs from the log.
// 3. "failed-to-verify-proof" - the monitor returned a proof of consistency
//    between the two STHs that did not verify.
// When the monitor fetches a consistency proof from the log it publishes the
// latency of the operation to the `sth_proof_latency` prometheus histogram.
func (f *sthFetcher) verifySTHConsistency(firstSTH, secondSTH *ct.SignedTreeHead) {
	if firstSTH == nil || secondSTH == nil {
		f.logErrorf("firstSTH or secondSTH was nil")
		return
	}

	firstTreeSize := firstSTH.TreeSize
	firstHash := firstSTH.SHA256RootHash[:]

	secondTreeSize := secondSTH.TreeSize
	secondHash := secondSTH.SHA256RootHash[:]

	// If the two STH's have equal tree sizes then we expect the SHA256RootHash to
	// match. If it doesn't match there is no need to check the consistency proofs
	// because the log is definitely inconsistent. In this case publish an
	// increment to the `sthInconsistencies` stat
	if firstTreeSize == secondTreeSize && !bytes.Equal(firstHash, secondHash) {
		errorLabels := prometheus.Labels{"uri": f.logURI, "type": "equal-treesize-inequal-hash"}
		f.stats.sthInconsistencies.With(errorLabels).Inc()
		f.logErrorf("first STH and second STH have same tree size (%d) "+
			"but different tree hashes. first.SHA256RootHash: %x "+
			"second.SHA256RootHash: %x",
			firstTreeSize,
			firstHash,
			secondHash)
		return
	} else if firstTreeSize == secondTreeSize {
		// If the two STH's have equal tree sizes and equal SHA256RootHashes there
		// isn't anything to do. We need STH's from two different tree states to
		// verify consistency
		f.logf("first STH and second STH have same SHA256RootHash (%x) "+
			"and tree size (%d). No consistency proof required",
			firstHash, firstTreeSize)
		return
	}

	// proofDescription is used in log messages to describe the proof being
	// fetched/verified
	proofDescription := fmt.Sprintf(
		"from treesize %d (hash %x) to treesize %d (hash %x)",
		firstTreeSize, firstHash, secondTreeSize, secondHash)

	// Fetch the consistency proof between the two tree sizes from the log.
	// Observe the latency of this operation using the `sthProofLatency` stat. If
	// the operation fails, consider it an inconsistency and publish an increment
	// to the `sthInconsistencies` stat.
	ctx, cancel := context.WithTimeout(context.Background(), f.sthTimeout)
	defer cancel()
	start := f.clk.Now()
	f.logf("Getting consistency proof %s", proofDescription)
	consistencyProof, err := f.client.GetSTHConsistency(ctx, firstTreeSize, secondTreeSize)
	elapsed := f.clk.Since(start)
	labels := prometheus.Labels{"uri": f.logURI}
	f.stats.sthProofLatency.With(labels).Observe(elapsed.Seconds())
	if err != nil {
		errorLabels := prometheus.Labels{"uri": f.logURI, "type": "failed-to-get-proof"}
		f.stats.sthInconsistencies.With(errorLabels).Inc()
		f.logErrorf("failed to get consistency proof %s: %q : %#v",
			proofDescription, err.Error(), err)
		return
	}

	// Verify the consistency proof. If the proof fails to verify then publish an
	// increment to the `sthInconsistencies` stat
	if err := f.verifier.VerifyConsistencyProof(
		int64(firstTreeSize),
		int64(secondTreeSize),
		firstHash,
		secondHash,
		consistencyProof); err != nil {
		errorLabels := prometheus.Labels{"uri": f.logURI, "type": "failed-to-verify-proof"}
		f.stats.sthInconsistencies.With(errorLabels).Inc()
		f.logErrorf("failed to verify consistency proof %s: %q : %#v",
			proofDescription, err.Error(), err)
		return
	}

	f.logf("verified consistency proof %s", proofDescription)
}
