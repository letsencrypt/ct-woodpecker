package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
)

func GETs(logURI string) {
	tests := []struct {
		Case           string
		Endpoint       string
		ExpectedStatus int
	}{
		// 	get-entries
		{
			Case:           "No range",
			Endpoint:       "get-entries",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only start",
			Endpoint:       "get-entries?start=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only end",
			Endpoint:       "get-entries?end=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int start",
			Endpoint:       "get-entries?start=a&end=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int end",
			Endpoint:       "get-entries?end=a&start=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "End before start",
			Endpoint:       "get-entries?start=1&end=0",
			ExpectedStatus: 400,
		},

		// 	get-sth-consistency
		{
			Case:           "No range",
			Endpoint:       "get-sth-consistency",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only first",
			Endpoint:       "get-sth-consistency?first=0",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only second",
			Endpoint:       "get-sth-consistency?second=0",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int first",
			Endpoint:       "get-sth-consistency?first=a",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int second",
			Endpoint:       "get-sth-consistency?second=b",
			ExpectedStatus: 400,
		},
		{
			Case:           "first before second",
			Endpoint:       "get-sth-consistency?second=0&first=1",
			ExpectedStatus: 400,
		},

		// 	get-proof-by-hash
		{
			Case:           "No hash or tree_size",
			Endpoint:       "get-proof-by-hash",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only hash",
			Endpoint:       "get-proof-by-hash?hash=AAAB",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only tree_size",
			Endpoint:       "get-proof-by-hash?tree_size=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid hash",
			Endpoint:       "get-proof-by-hash?hash=ff&tree_size=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid tree_size",
			Endpoint:       "get-proof-by-hash?tree_size=0&hash=AAAB&hash=AAAB",
			ExpectedStatus: 400,
		},

		// 	get-entry-and-proof
		{
			Case:           "No leaf_index or tree_size",
			Endpoint:       "get-entry-and-proof",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only tree_size",
			Endpoint:       "get-entry-and-proof?tree_size=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only leaf_index",
			Endpoint:       "get-entry-and-proof?leaf_index=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int tree_size",
			Endpoint:       "get-entry-and-proof?tree_size=a&leaf_index=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int leaf_index",
			Endpoint:       "get-entry-and-proof?tree_size=1&leaf_index=a",
			ExpectedStatus: 400,
		},
		{
			Case:           "leaf_index out of range",
			Endpoint:       "get-entry-and-proof?tree_size=1&leaf_index=5",
			ExpectedStatus: 400,
		},
	}

	hc := new(http.Client)

	for _, tc := range tests {
		fmt.Printf("%s -- %s... ", tc.Endpoint, tc.Case)
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/ct/v1/%s", logURI, tc.Endpoint), nil)
		if err != nil {
			panic(err)
		}
		rsp, err := hc.Do(req)
		if err != nil {
			fmt.Printf("FAILED: %s\n", err)
			os.Exit(1)
		}
		if rsp.StatusCode != tc.ExpectedStatus {
			fmt.Printf("FAILED: expected %d, got %d\n", tc.ExpectedStatus, rsp.StatusCode)
			os.Exit(1)
		}
		fmt.Printf("OK\n")
	}
}

func POSTs(logURI string) {
	tests := []struct {
		Case           string
		Endpoint       string
		Body           string
		ExpectedStatus int
	}{
		// add-chain
		{
			Case:           "Empty body",
			Endpoint:       "add-chain",
			Body:           "",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty JSON object",
			Endpoint:       "add-chain",
			Body:           "{}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Unknown key",
			Endpoint:       "add-chain",
			Body:           "{\"hello there\": \"general kenobi\"}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty chain",
			Endpoint:       "add-chain",
			Body:           "{\"chain\":[]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid entry",
			Endpoint:       "add-chain",
			Body:           "{\"chain\":[\"\"]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid DER",
			Endpoint:       "add-chain",
			Body:           "{\"chain\":[\"xxx\"]}",
			ExpectedStatus: 400,
		},

		// add-pre-chain
		{
			Case:           "Empty body",
			Endpoint:       "add-pre-chain",
			Body:           "",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty JSON object",
			Endpoint:       "add-pre-chain",
			Body:           "{}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Unknown key",
			Endpoint:       "add-pre-chain",
			Body:           "{\"hello there\": \"general kenobi\"}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty chain",
			Endpoint:       "add-pre-chain",
			Body:           "{\"chain\":[]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid entry",
			Endpoint:       "add-pre-chain",
			Body:           "{\"chain\":[\"\"]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid DER",
			Endpoint:       "add-pre-chain",
			Body:           "{\"chain\":[\"xxx\"]}",
			ExpectedStatus: 400,
		},
	}

	hc := new(http.Client)

	for _, tc := range tests {
		fmt.Printf("%s %s -- %s... ", tc.Endpoint, tc.Body, tc.Case)
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/ct/v1/%s", logURI, tc.Endpoint), bytes.NewBuffer([]byte(tc.Body)))
		if err != nil {
			panic(err)
		}
		rsp, err := hc.Do(req)
		if err != nil {
			fmt.Printf("FAILED: %s\n", err)
			os.Exit(1)
		}
		if rsp.StatusCode != tc.ExpectedStatus {
			fmt.Printf("FAILED: expected %d, got %d\n", tc.ExpectedStatus, rsp.StatusCode)
			os.Exit(1)
		}
		fmt.Printf("OK\n")
	}
}

func main() {
	logURL := flag.String("log", "", "log URL to test against")
	flag.Parse()

	fmt.Println("Running GET tests")
	GETs(*logURL)

	fmt.Println("\nRunning POST tests")
	POSTs(*logURL)
}
