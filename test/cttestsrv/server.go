package cttestsrv

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/certificate-transparency-go"
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

	// sth is the mock SignedTreeHead the server returns for get-sth requests
	sth *ct.SignedTreeHead
	// sthFetches tracks how many times get-sth has been called
	sthFetches int64
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
	is := &IntegrationSrv{
		logger:          logger,
		Addr:            p.Addr,
		PubKey:          base64.StdEncoding.EncodeToString(pubKeyBytes),
		key:             key,
		latencySchedule: p.LatencySchedule,
		server: &http.Server{
			Addr: p.Addr,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/add-pre-chain", is.addChainHandler)
	mux.HandleFunc("/ct/v1/add-chain", is.addChainHandler)
	mux.HandleFunc("/submissions", is.getSubmissionsHandler)
	mux.HandleFunc("/ct/v1/get-sth", is.getSTHHandler)
	mux.HandleFunc("/set-sth", is.setSTHHandler)
	mux.HandleFunc("/sth-fetches", is.getSTHFetchesHandler)
	is.server.Handler = mux
	return is, nil
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

func (is *IntegrationSrv) sleep() {
	if is.latencySchedule != nil {
		is.Lock()
		sleepTime := time.Duration(is.latencySchedule[is.latencyItem%len(is.latencySchedule)]) * time.Second
		is.latencyItem++
		is.Unlock()
		time.Sleep(sleepTime)
	}
}

// addChain returns the raw bytes of a signed testing SCT for the given chain
// (or an error). The submissions count will be incremented as a result. This
// function blocks for a variable amount of time based on the latencySchedule
// and the current latencyItem index. It is safe to call concurrently.
func (is *IntegrationSrv) addChain(chain []string, precert bool) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("chain argument must have len >= 1")
	}

	is.sleep()
	atomic.AddInt64(&is.submissions, 1)
	return createTestingSignedSCT(chain, is.key, precert, time.Now()), nil
}

// addChainHandler handles a HTTP POST for the add-chain and add-pre-chain CT
// endpoint.
func (is *IntegrationSrv) addChainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var addChainReq struct {
		Chain []string
	}
	err = json.Unmarshal(bodyBytes, &addChainReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	precert := false
	if r.URL.Path == "/ct/v1/add-pre-chain" {
		precert = true
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()
	sct, err := is.addChain(addChainReq.Chain, precert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sct)
}

// Submissions returns the number of add-chain/add-pre-chain requests processed
// so far. It is safe to call concurrently.
func (is *IntegrationSrv) Submissions() int64 {
	return atomic.LoadInt64(&is.submissions)
}

// getSubmissions handler allows fetching the number of add-chain/add-pre-chain
// requests processed so far using an HTTP GET request.
func (is *IntegrationSrv) getSubmissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", is.Submissions())
	is.logger.Printf("%s %s request completed.", is.Addr, r.URL.Path)
}

// getSTHHandler processes GET requests for the CT get-sth endpoint. It returns
// the server's current mock STH. The number of sthFetches seen by the server is
// incremented as a result of processing the request.
func (is *IntegrationSrv) getSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()
	is.sleep()
	// Track that an STH was fetched
	atomic.AddInt64(&is.sthFetches, 1)

	is.RLock()
	defer is.RUnlock()
	response, err := json.Marshal(&is.sth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", response)
}

// SetSTH allows setting the server's mock STH. It is safe to call concurrently.
func (is *IntegrationSrv) SetSTH(mockSTH *ct.SignedTreeHead) {
	_ = signSTH(is.key, mockSTH)
	is.Lock()
	defer is.Unlock()
	is.sth = mockSTH
}

// SetSTHHandler allows setting the server's mock STH through a HTTP POST
// request.
func (is *IntegrationSrv) setSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mockSTH struct {
		TreeSize  uint64 `json:"tree_size"`
		Timestamp uint64
		RootHash  string `json:"sha256_root_hash"`
	}
	err = json.Unmarshal(msg, &mockSTH)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var root ct.SHA256Hash
	err = root.FromBase64String(mockSTH.RootHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sth := &ct.SignedTreeHead{
		TreeSize:       mockSTH.TreeSize,
		Timestamp:      mockSTH.Timestamp,
		SHA256RootHash: root,
	}
	is.SetSTH(sth)
	w.WriteHeader(http.StatusOK)
}

// STHFetches returns the number of get-sth requests processed by the server so
// far. It is safe to call concurrently.
func (is *IntegrationSrv) STHFetches() int64 {
	return atomic.LoadInt64(&is.sthFetches)
}

// getSTHFetchesHandler allows fetching the number of get-sth requests processed
// by the server so far by sending a HTTP GET request.
func (is *IntegrationSrv) getSTHFetchesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", is.STHFetches())
}
