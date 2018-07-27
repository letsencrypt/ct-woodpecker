package cttestsrv

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
)

// Personality describes the configuration & behaviour of a test CT
// IntegrationSrv
type Personality struct {
	// Port (and optionally IP) to listen on
	Addr string
	// Base64 encoded private key for signing SCTs
	// Generate your own with:
	// openssl ecparam -name prime256v1 -genkey -outform der -noout | base64 -w 0
	PrivKey string
	// If present, sleep for the given number of seconds before replying. Each
	// request uses the next number in the list, eventually cycling through.
	LatencySchedule []float64
}

// IntegrationSrv is an instance of a CT test server.
type IntegrationSrv struct {
	sync.RWMutex
	logger *log.Logger

	// key is the log's private key used to sign STHs and SCTs
	key *ecdsa.PrivateKey

	// PubKey is the log's public key in base64 encoded format
	PubKey string

	// latencySchedule holds the latency schedule from the Personality that was
	// used to create the IntegrationSrv instance. This controls the latency
	// pattern of add-chain/add-pre-chain responses.
	latencySchedule []float64
	// latencyItem is the index into the latencySchedule used for the next
	// add-chain/add-pre-chain.
	latencyItem int

	// server is the HTTP server listening for CT requests
	server *http.Server
	// Addr is the address the *http.Server above is listening on (used for
	// clarifying log messages)
	Addr string

	// submissions tracks how many certificate chains have been added through
	// add-chain and add-pre-chain
	submissions int64

	// sth is a mock SignedTreeHead the server returns for get-sth requests when
	// it is not nil. Otherwise the testLog's real STH is used.
	sth *ct.SignedTreeHead

	// sthFetches tracks how many times get-sth has been called
	sthFetches int64

	// testLog is an in-memory Trillian CT log tailored for testing ct-woodpecker
	log *testLog
}

// NewServer creates an IntegrationSrv instance with the given Personality,
// logging to the given logger. The returned IntegrationSrv instance will not be
// started until Run() is called.
func NewServer(p Personality, logger *log.Logger) (*IntegrationSrv, error) {
	keyDER, err := base64.StdEncoding.DecodeString(p.PrivKey)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	testLog, err := newLog(key)
	if err != nil {
		return nil, err
	}
	is := &IntegrationSrv{
		logger:          logger,
		Addr:            p.Addr,
		PubKey:          base64.StdEncoding.EncodeToString(pubKeyBytes),
		key:             key,
		latencySchedule: p.LatencySchedule,
		server: &http.Server{
			Addr: p.Addr,
		},
		log: testLog,
	}
	mux := http.NewServeMux()
	// Certificate Transparency Log API endpoints. See `handlers.go`
	mux.HandleFunc(ct.AddPreChainPath, is.addChainHandler)
	mux.HandleFunc(ct.AddChainPath, is.addChainHandler)
	mux.HandleFunc(ct.GetSTHPath, is.getSTHHandler)
	mux.HandleFunc(ct.GetSTHConsistencyPath, is.getConsistencyHandler)
	mux.HandleFunc(ct.GetEntriesPath, is.getEntriesHandler)
	// Test server management endpoints. See `management_handlers.go`
	mux.HandleFunc("/integrate", is.integrateHandler)
	mux.HandleFunc("/set-sth", is.setSTHHandler)
	mux.HandleFunc("/clear-sth", is.clearSTHHandler)
	mux.HandleFunc("/switch-trees", is.switchTreesHandler)
	mux.HandleFunc("/submissions", is.getSubmissionsHandler)
	mux.HandleFunc("/sth-fetches", is.getSTHFetchesHandler)
	is.server.Handler = mux
	return is, nil
}

// sleep is called by CT API functions to sleep a variable amount of time based
// on the latencySchedule and the latencyItem index.
func (is *IntegrationSrv) sleep() {
	if is.latencySchedule != nil {
		is.Lock()
		sleepTime := time.Duration(is.latencySchedule[is.latencyItem%len(is.latencySchedule)]) * time.Second
		is.latencyItem++
		is.Unlock()
		time.Sleep(sleepTime)
	}
}

// Run starts an IntegrationSrv instance by calling ListenAndServe on the
// integration server's *http.Server in a dedicated goroutine.
func (is *IntegrationSrv) Run() {
	is.logger.Printf("Running cttestsrv instance on %s with pubkey %s",
		is.Addr, is.PubKey)
	go func() {
		if err := is.server.ListenAndServe(); err != nil {
			is.logger.Printf("%s ListenAndServe error: %s", is.Addr, err.Error())
		}
	}()
}

// Shutdown cleanly stops the IntegrationSrv's *http.Server.
func (is *IntegrationSrv) Shutdown() {
	is.logger.Printf("Stopping server on %s", is.Addr)
	_ = is.server.Shutdown(context.Background())
}

// SwitchTrees changes the active testLog tree and returns the DisplayName of
// the newly activated tree.
func (is *IntegrationSrv) SwitchTrees() string {
	newTree := is.log.switchTrees()
	is.logger.Printf("Switched backing tree to %s", newTree.tree.DisplayName)
	return newTree.tree.DisplayName
}

// GetSTH returns a GetSTHResponse containing either the mockSTH (if not nil) or
// the STH of the testlog's active tree. The sthFetches count is incremented as
// a result of this function being called. This function blocks for a variable
// amount of time based on the latencySchedule and the current latencyItem
// index. It is safe to call concurrently.
func (is *IntegrationSrv) GetSTH() (*ct.GetSTHResponse, error) {
	is.sleep()

	is.RLock()
	defer is.RUnlock()

	// Track that an STH was fetched
	atomic.AddInt64(&is.sthFetches, 1)

	// If there is a mock STH, use it
	var sth *ct.SignedTreeHead
	var err error
	if is.sth != nil {
		sth = is.sth
	} else {
		// Otherwise, get the testlog's STH and use it
		sth, err = is.log.getSTH()
		if err != nil {
			return nil, err
		}
	}

	marshaledSig, err := cttls.Marshal(sth.TreeHeadSignature)
	if err != nil {
		return nil, err
	}

	curSTHResp := &ct.GetSTHResponse{
		TreeSize:          sth.TreeSize,
		SHA256RootHash:    sth.SHA256RootHash[:],
		Timestamp:         sth.Timestamp,
		TreeHeadSignature: marshaledSig,
	}
	return curSTHResp, nil
}

// GetEntries returns a GetEntriesResponse with the requested entries for the
// currently active testLog tree. This function blocks for a variable amount of
// time based on the latencySchedule and the current latencyItem index. It is
// safe to call concurrently.
func (is *IntegrationSrv) GetEntries(start, end int64) (*ct.GetEntriesResponse, error) {
	is.sleep()

	is.RLock()
	defer is.RUnlock()

	is.logger.Printf("Getting entries from %d to %d (%d entries)", start, end, (end - start))
	entries, err := is.log.getEntries(start, end)
	if err != nil {
		return nil, err
	}

	resp := ct.GetEntriesResponse{}
	for _, leaf := range entries {
		resp.Entries = append(resp.Entries, ct.LeafEntry{
			LeafInput: leaf.LeafValue,
			ExtraData: leaf.ExtraData,
		})
	}

	return &resp, nil
}

// GetConsistencyProof returns a GetSTHConsistencyResponse for the currently
// active testLog tree between the two requested treesizes. This function blocks
// for a variable amount of time based on the latencySchedule and the current
// latencyItem index. It is safe to call concurrently.
func (is *IntegrationSrv) GetConsistencyProof(first, second int64) (*ct.GetSTHConsistencyResponse, error) {
	is.sleep()

	is.RLock()
	defer is.RUnlock()

	is.logger.Printf("Getting consistency proof from %d to %d", first, second)
	proof, err := is.log.getProof(first, second)
	if err != nil {
		return nil, err
	}

	return &ct.GetSTHConsistencyResponse{
		Consistency: proof.Proof.Hashes,
	}, nil
}

// AddChain returns a ct.AddChainResponse with an SCT for the provided chain
// (or an error). The chain will be queued by the testlog's currently active
// tree. The queue will not be sequenced until integrateBatch is called. The
// submissions count will be incremented as a result. This
// function blocks for a variable amount of time based on the latencySchedule
// and the current latencyItem index. It is safe to call concurrently.
func (is *IntegrationSrv) AddChain(chain []ct.ASN1Cert, precert bool) (*ct.AddChainResponse, error) {
	is.sleep()

	is.Lock()
	defer is.Unlock()

	if len(chain) == 0 {
		return nil, errors.New("chain argument must have len >= 1")
	}

	// Add the chain to the test log, getting back an SCT
	sct, err := is.log.addChain(chain, precert)
	if err != nil {
		return nil, err
	}
	atomic.AddInt64(&is.submissions, 1)
	is.logger.Printf("Queued 1 new chain. %d total submissions.", atomic.LoadInt64(&is.submissions))

	// Marshal the SCT's digitally signed signature struct to raw bytes
	sigBytes, err := cttls.Marshal(sct.Signature)
	if err != nil {
		return nil, err
	}

	return &ct.AddChainResponse{
		SCTVersion: sct.SCTVersion,
		ID:         sct.LogID.KeyID[:],
		Timestamp:  sct.Timestamp,
		Extensions: base64.StdEncoding.EncodeToString(sct.Extensions),
		Signature:  sigBytes,
	}, nil
}

// SetSTH allows setting the server's mock STH. It is safe to call concurrently.
func (is *IntegrationSrv) SetSTH(mockSTH *ct.SignedTreeHead) error {
	is.Lock()
	defer is.Unlock()
	if err := is.log.signSTH(mockSTH); err != nil {
		return err
	}
	is.sth = mockSTH
	is.logger.Printf("Set STH to provided mock STH: %#v\n", mockSTH)
	return nil
}

// Integrate uses the testLog's currently active tree to sequence up to `count`
// queued leaves. The number of leaves sequenced is returned. If more than `count`
// leaves are queued Integrate will need to be called multiple times to fully
// process the log's queue of unsequenced leaves. It is safe to call concurrently.
func (is *IntegrationSrv) Integrate(count int64) (int, error) {
	integratedCount, err := is.log.integrateBatch(count)
	if err != nil {
		return 0, err
	}

	is.logger.Printf("Integrated %d new leave(s)", integratedCount)
	return integratedCount, nil
}

// Submissions returns the number of add-chain/add-pre-chain requests processed
// so far. It is safe to call concurrently.
func (is *IntegrationSrv) Submissions() int64 {
	return atomic.LoadInt64(&is.submissions)
}

// STHFetches returns the number of get-sth requests processed by the server so
// far. It is safe to call concurrently.
func (is *IntegrationSrv) STHFetches() int64 {
	return atomic.LoadInt64(&is.sthFetches)
}
