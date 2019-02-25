package cttestsrv

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/letsencrypt/ct-woodpecker/test"
)

// setSTHHandler allows setting the server's mock STH through a HTTP POST
// request. When a mockSTH is set it will be returned for all getSTH requests
// regardless of the testlog's activeTree's state. In order to get the "real"
// STH again the `clearSTHHandler` must be called.
func (is *IntegrationSrv) setSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPPOST {
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
	if err := is.SetSTH(sth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// clearSTHHandler clears out any mockSTH's set with the setSTHHandler.
// Subsequent getSTH requests to the log will return the "real" STH from the
// testlog's active tree.
func (is *IntegrationSrv) clearSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPGET {
		http.NotFound(w, r)
		return
	}

	if err := is.SetSTH(nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)
}

// integrateHandler accepts GET requests indicating the testLog's activeTree
// should sequence a batch of unintegrated leaves that have been submitted
// through the add chains endpoint. The maximum number of unsequenced leaves to
// process is specified by the count HTTP get parameter (and defaults to 50 if
// not provided). The number of sequenced leaves is returned as the HTTP
// response body.
func (is *IntegrationSrv) integrateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPGET {
		http.NotFound(w, r)
		return
	}

	count := int64(50)

	countArgs, ok := r.URL.Query()["count"]
	if ok && len(countArgs) == 1 {
		countArg, err := strconv.ParseInt(countArgs[0], 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		count = countArg
	}

	integratedCount, err := is.Integrate(count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", integratedCount)
	is.logger.Printf("%s %s request completed.", is.Addr, r.URL.Path)
}

// getSubmissions handler allows fetching the number of add-chain/add-pre-chain
// requests processed so far using an HTTP GET request.
func (is *IntegrationSrv) getSubmissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPGET {
		http.NotFound(w, r)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", is.Submissions())
	is.logger.Printf("%s %s request completed.", is.Addr, r.URL.Path)
}

// getSTHFetchesHandler allows fetching the number of get-sth requests processed
// by the server so far by sending a HTTP GET request.
func (is *IntegrationSrv) getSTHFetchesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPGET {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", is.STHFetches())
}

func (is *IntegrationSrv) switchTreesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPGET {
		http.NotFound(w, r)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	_ = is.SwitchTrees()
	is.logger.Printf("%s %s request completed.", is.Addr, r.URL.Path)
	w.WriteHeader(http.StatusOK)
}

// the alertWebhookHandler dumps any POST bodies sent to it to the logger. This
// is used in CI for dumping Alertmanager POSTs somewhere they'll appear in
// stdout without needing to run a separate service just to echo a webhook POST.
func (is *IntegrationSrv) alertWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPPOST {
		http.NotFound(w, r)
		return
	}

	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	is.logger.Printf("%s %s request: \n%s\n", is.Addr, r.URL.Path, string(msg))
	w.WriteHeader(http.StatusOK)
}

func (is *IntegrationSrv) addMockResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPPOST {
		http.NotFound(w, r)
		return
	}

	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mockResponse struct {
		Path     string
		Code     int
		Response interface{}
	}

	err = json.Unmarshal(msg, &mockResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if mockResponse.Path == "" {
		http.Error(
			w,
			"Mock response Path must not be empty",
			http.StatusBadRequest)
		return
	}

	is.AddMockResponse(mockResponse.Path, mockResponse.Code, mockResponse.Response)
	is.logger.Printf(
		"%s %s request completed - added mock response for %q.",
		is.Addr, r.URL.Path, mockResponse.Path)
	w.WriteHeader(http.StatusOK)
}

func (is *IntegrationSrv) removeMockResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != test.HTTPPOST {
		http.NotFound(w, r)
		return
	}

	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mockResponse struct {
		Path string
	}

	err = json.Unmarshal(msg, &mockResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if mockResponse.Path == "" {
		http.Error(
			w,
			"Mock response Path must not be empty",
			http.StatusBadRequest)
		return
	}

	is.RemoveMockResponse(mockResponse.Path)
	is.logger.Printf(
		"%s %s request completed - removed mock response for %q.",
		is.Addr, r.URL.Path, mockResponse.Path)
	w.WriteHeader(http.StatusOK)
}
