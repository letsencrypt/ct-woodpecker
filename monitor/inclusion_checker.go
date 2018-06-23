package monitor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/ct-woodpecker/storage"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var oldestUnseen = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "oldest_unincorporated_cert",
	Help: "Number of seconds since the oldest unincorporated certificate was submitted",
})

type InclusionOptions struct {
	Interval       time.Duration
	FetchBatchSize int64
}

type inclusionChecker struct {
	logger           *log.Logger
	client           monitorCTClient
	logURI           string
	db               storage.Storage
	signatureChecker *ct.SignatureVerifier
	clk              clock.Clock
	logID            int64

	interval  time.Duration
	batchSize int64
}

func (ic *inclusionChecker) run() {
	go func() {
		for {
			ic.checkInclusion()
			ic.clk.Sleep(ic.interval)
		}
	}()
}

func (ic *inclusionChecker) checkInclusion() {
	current, err := ic.db.GetIndex(ic.logID)
	if err != nil {
		ic.logger.Printf("!!! Failed to get current log index: %s", err)
		return
	}

	certs, err := ic.db.GetUnseen(ic.logID)
	if err != nil {
		ic.logger.Printf("!!! Failed to get unseen certificates: %s", err)
		return
	}
	if len(certs) == 0 {
		// nothing to do, don't advance the index
		return
	}

	sth, err := ic.client.GetSTH(context.Background())
	if err != nil {
		ic.logger.Printf("!!! Failed to get STH: %s", err)
		return
	}
	newHead, entries, err := ic.getEntries(current, int64(sth.TreeSize))
	if err != nil {
		ic.logger.Printf("!!! Failed to retrieve entries: %s", err)
		return
	}

	err = ic.checkEntries(certs, entries)
	if err != nil {
		ic.logger.Printf("!!! Failed to check entries against unseen certificates: %s", err)
		return
	}

	err = ic.db.UpdateIndex(ic.logID, newHead)
	if err != nil {
		ic.logger.Printf("!!! Failed to update current log index: %s", err)
		return
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (ic *inclusionChecker) getEntries(start, end int64) (int64, []ct.LogEntry, error) {
	var allEntries []ct.LogEntry
	for start <= end {
		batchEnd := min(start+ic.batchSize, end)
		entries, err := ic.client.GetEntries(context.Background(), start, batchEnd)
		if err != nil {
			return 0, nil, err
		}
		allEntries = append(allEntries, entries...)
		start += int64(len(entries))
	}
	return start, allEntries, nil
}

func (ic *inclusionChecker) checkEntries(certs []storage.SubmittedCert, entries []ct.LogEntry) error {
	lookup := make(map[string]storage.SubmittedCert)
	for _, cert := range certs {
		h := sha256.Sum256(cert.Cert)
		lookup[fmt.Sprintf("%x", h)] = cert
	}
	for _, entry := range entries {
		var h [32]byte
		switch entry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			h = sha256.Sum256(entry.X509Cert.Raw)
		case ct.PrecertLogEntryType:
			h = sha256.Sum256(entry.Precert.Submitted.Data)
		}
		if matching, found := lookup[fmt.Sprintf("%x", h)]; found {
			var sct ct.SignedCertificateTimestamp
			_, err := tls.Unmarshal(matching.SCT, &sct)
			if err != nil {
				return fmt.Errorf("error unmarshalling SCT: %s", err)
			}
			if sct.Timestamp != entry.Leaf.TimestampedEntry.Timestamp {
				// this is not the entry we are looking for
				continue
			}
			err = ic.signatureChecker.VerifySCTSignature(sct, entry)
			if err != nil {
				return fmt.Errorf("error verifying SCT signature: %s", err)
			}
			err = ic.db.MarkCertSeen(matching.ID, ic.clk.Now().UnixNano())
			if err != nil {
				return fmt.Errorf("error marking certificate as seen: %s", err)
			}
			delete(lookup, fmt.Sprintf("%x", h))
		}
	}

	var oldest int64
	for _, unseen := range lookup {
		if oldest == 0 || unseen.Timestamp < oldest {
			oldest = unseen.Timestamp
		}
	}
	oldestUnseen.Set(ic.clk.Since(time.Unix(0, oldest)).Seconds())

	return nil
}
