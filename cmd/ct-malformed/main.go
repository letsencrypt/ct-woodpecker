package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/google/certificate-transparency-go"
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
			Endpoint:       string(ct.GetEntriesStr),
			ExpectedStatus: 400,
		},
		{
			Case:           "Only start",
			Endpoint:       string(ct.GetEntriesStr) + "?start=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only end",
			Endpoint:       string(string(ct.GetEntriesStr)) + "?end=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int start",
			Endpoint:       string(ct.GetEntriesStr) + "?start=a&end=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int end",
			Endpoint:       string(ct.GetEntriesStr) + "?end=a&start=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "End before start",
			Endpoint:       string(ct.GetEntriesStr) + "?start=1&end=0",
			ExpectedStatus: 400,
		},
		{
			Case:           "Negative start, positive end",
			Endpoint:       string(ct.GetEntriesStr) + "?start=-100&end=10",
			ExpectedStatus: 400,
		},
		{
			Case:           "Positive start, negative end",
			Endpoint:       string(ct.GetEntriesStr) + "?start=100&end=-10",
			ExpectedStatus: 400,
		},
		{
			Case:           "Negative start and end",
			Endpoint:       string(ct.GetEntriesStr) + "?start=-100&end=-10",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point start",
			Endpoint:       string(ct.GetEntriesStr) + "?start=1.5&end=100",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point end",
			Endpoint:       string(ct.GetEntriesStr) + "?start=1&end=100.5",
			ExpectedStatus: 400,
		},
		{
			Case:           "start larger than biggest unsigned int",
			Endpoint:       string(ct.GetEntriesStr) + "?start=18446744073709551616&end=18446744073709551620",
			ExpectedStatus: 400,
		},

		// 	get-sth-consistency
		{
			Case:           "No range",
			Endpoint:       string(ct.GetSTHConsistencyStr),
			ExpectedStatus: 400,
		},
		{
			Case:           "Only first",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?first=0",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only second",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=0",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int first",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?first=a",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int second",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=b",
			ExpectedStatus: 400,
		},
		{
			Case:           "second before first",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=0&first=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "first negative",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=10&first=-1",
			ExpectedStatus: 400,
		},
		{
			Case:           "second negative",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=-10&first=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "first and second negative",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=-10&first=-20",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point first",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=20&first=10.5",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point second",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=20.5&first=10",
			ExpectedStatus: 400,
		},
		{
			Case:           "first larger than biggest unsigned int",
			Endpoint:       string(ct.GetSTHConsistencyStr) + "?second=18446744073709551620&first=18446744073709551616",
			ExpectedStatus: 400,
		},

		// 	get-proof-by-hash
		{
			Case:           "No hash or tree_size",
			Endpoint:       string(ct.GetProofByHashStr),
			ExpectedStatus: 400,
		},
		{
			Case:           "Only hash",
			Endpoint:       string(ct.GetProofByHashStr) + "?hash=AAAB",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only tree_size",
			Endpoint:       string(ct.GetProofByHashStr) + "?tree_size=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid hash",
			Endpoint:       string(ct.GetProofByHashStr) + "?hash=ff&tree_size=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Zero tree_size",
			Endpoint:       string(ct.GetProofByHashStr) + "?tree_size=0&hash=AAAB&hash=AAAB",
			ExpectedStatus: 400,
		},
		{
			Case:           "Negative tree_size",
			Endpoint:       string(ct.GetProofByHashStr) + "?tree_size=-10&hash=AAAB&hash=AAAB",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point tree_size",
			Endpoint:       string(ct.GetProofByHashStr) + "?tree_size=10.5&hash=AAAB&hash=AAAB",
			ExpectedStatus: 400,
		},
		{
			Case:           "tree_size larger than biggest unsigned int",
			Endpoint:       string(ct.GetProofByHashStr) + "?tree_size=18446744073709551616&hash=AAAB&hash=AAAB",
			ExpectedStatus: 400,
		},

		// 	get-entry-and-proof
		{
			Case:           "No leaf_index or tree_size",
			Endpoint:       string(ct.GetEntryAndProofStr),
			ExpectedStatus: 400,
		},
		{
			Case:           "Only tree_size",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Only leaf_index",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?leaf_index=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int tree_size",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=a&leaf_index=1",
			ExpectedStatus: 400,
		},
		{
			Case:           "Non-int leaf_index",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=1&leaf_index=a",
			ExpectedStatus: 400,
		},
		{
			Case:           "leaf_index out of range",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=1&leaf_index=5",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point leaf_index",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=100&leaf_index=5.5",
			ExpectedStatus: 400,
		},
		{
			Case:           "Floating point tree_size",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=100.5&leaf_index=5",
			ExpectedStatus: 400,
		},
		{
			Case:           "Negative leaf_index",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=100&leaf_index=-5",
			ExpectedStatus: 400,
		},
		{
			Case:           "Negative tree_size",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=-1&leaf_index=5",
			ExpectedStatus: 400,
		},
		{
			Case:           "tree_size larger than biggest unsigned int",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=18446744073709551616&leaf_index=5",
			ExpectedStatus: 400,
		},
		{
			Case:           "tree_size and leaf larger than biggest unsigned int",
			Endpoint:       string(ct.GetEntryAndProofStr) + "?tree_size=18446744073709551620&leaf_index=18446744073709551616",
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
			Endpoint:       string(ct.AddChainStr),
			Body:           "",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty JSON object",
			Endpoint:       string(ct.AddChainStr),
			Body:           "{}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Unknown key",
			Endpoint:       string(ct.AddChainStr),
			Body:           "{\"hello there\": \"general kenobi\"}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty chain",
			Endpoint:       string(ct.AddChainStr),
			Body:           "{\"chain\":[]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid entry",
			Endpoint:       string(ct.AddChainStr),
			Body:           "{\"chain\":[\"\"]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid B64",
			Endpoint:       string(ct.AddChainStr),
			Body:           "{\"chain\":[\"xxx\"]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid DER",
			Endpoint:       string(ct.AddChainStr),
			Body:           "{\"chain\":[\"aXQncyBvdmVyIGFuYWtpbiEgaSBoYXZlIHRoZSBoaWdoIGdyb3VuZCE=\"]}",
			ExpectedStatus: 400,
		},

		// add-pre-chain
		{
			Case:           "Empty body",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty JSON object",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "{}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Unknown key",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "{\"hello there\": \"general kenobi\"}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Empty chain",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "{\"chain\":[]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid entry",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "{\"chain\":[\"\"]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid B64",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "{\"chain\":[\"xxx\"]}",
			ExpectedStatus: 400,
		},
		{
			Case:           "Invalid DER",
			Endpoint:       string(ct.AddPreChainStr),
			Body:           "{\"chain\":[\"aXQncyBvdmVyIGFuYWtpbiEgaSBoYXZlIHRoZSBoaWdoIGdyb3VuZCE=\"]}",
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
