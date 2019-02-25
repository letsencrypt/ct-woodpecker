package cttestsrv

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/letsencrypt/ct-woodpecker/test"
)

func (is *IntegrationSrv) tryServeMock(w http.ResponseWriter, r *http.Request) bool {
	if mock := is.GetMockResponse(r.URL.Path); mock != nil {
		response, err := json.Marshal(mock.Response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		is.logger.Printf("%s %s request completed with mock response",
			is.Addr, r.URL.Path)
		w.WriteHeader(mock.Code)
		fmt.Fprintf(w, "%s", response)
		return true
	}
	return false
}

// getSTHHandler processes GET requests for the CT get-sth endpoint. If no mock
// STH has been set with the setSTHHandler then the getSTHHandler marshals the
// currently active testlog tree's STH. If a mock STH has been set then the
// getSTHHandler ignores the active testlog tree and returns the mock STH.
// The number of sthFetches seen by the server is incremented as a result of
// processing the request.
func (is *IntegrationSrv) getSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTP_GET {
		http.NotFound(w, r)
		return
	}

	if is.tryServeMock(w, r) {
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()

	curSTHResp, err := is.GetSTH()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(&curSTHResp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", response)
}

// addChainHandler handles a HTTP POST for the add-chain and add-pre-chain CT
// endpoint. The provided chain will be queued for submission with the currently
// active testlog tree. The count of submissions seen by the server is
// incremented as a result of processing the request.
func (is *IntegrationSrv) addChainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTP_POST {
		http.NotFound(w, r)
		return
	}

	if is.tryServeMock(w, r) {
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

	chain := make([]ct.ASN1Cert, len(addChainReq.Chain))
	for i, certBase64 := range addChainReq.Chain {
		b, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		chain[i] = ct.ASN1Cert{Data: b}
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()

	precert := false
	if r.URL.Path == "/ct/v1/add-pre-chain" {
		precert = true
	}

	resp, err := is.AddChain(chain, precert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// getEntriesHandler handles CT API requests for the get-entries endpoint. It
// returns incorporated entries from the currently active testlog tree.
func (is *IntegrationSrv) getEntriesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTP_GET {
		http.NotFound(w, r)
		return
	}

	if is.tryServeMock(w, r) {
		return
	}

	startArgs, ok := r.URL.Query()["start"]
	if !ok || len(startArgs) < 1 {
		http.Error(w, "no start parameter", http.StatusBadRequest)
		return
	}
	endArgs, ok := r.URL.Query()["end"]
	if !ok || len(endArgs) < 1 {
		http.Error(w, "no end parameter", http.StatusBadRequest)
		return
	}

	start, err := strconv.ParseInt(startArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	end, err := strconv.ParseInt(endArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	startTime := time.Now()

	resp, err := is.GetEntries(start, end)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respBytes, err := json.Marshal(&resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(startTime)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", respBytes)
}

// getConsistencyHandler handles CT API requests for the get-sth-consistency
// endpoint. It returns a consistency proof from the currently active testlog's
// tree.
func (is *IntegrationSrv) getConsistencyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTP_GET {
		http.NotFound(w, r)
		return
	}

	if is.tryServeMock(w, r) {
		return
	}

	firstArgs, ok := r.URL.Query()["first"]
	if !ok || len(firstArgs) < 1 {
		http.Error(w, "no first parameter", http.StatusBadRequest)
		return
	}
	secondArgs, ok := r.URL.Query()["second"]
	if !ok || len(secondArgs) < 1 {
		http.Error(w, "no second parameter", http.StatusBadRequest)
		return
	}

	first, err := strconv.ParseInt(firstArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	second, err := strconv.ParseInt(secondArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()

	resp, err := is.GetConsistencyProof(first, second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respBytes, err := json.Marshal(&resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", respBytes)
}
