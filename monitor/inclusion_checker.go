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
			err := ic.checkInclusion()
			if err != nil {
				ic.logger.Printf("!!! Checking certificate inclusion failed: %s", err)
			}
			ic.clk.Sleep(ic.interval)
		}
	}()
}

func (ic *inclusionChecker) checkInclusion() error {
	current, err := ic.db.GetIndex(ic.logID)
	if err != nil {
		return fmt.Errorf("error getting current log index: %s", err)
	}

	certs, err := ic.db.GetUnseen(ic.logID)
	if err != nil {
		return fmt.Errorf("error getting unseen certificates: %s", err)
	}
	if len(certs) == 0 {
		// nothing to do, don't advance the index
		return nil
	}

	sth, err := ic.client.GetSTH(context.Background())
	if err != nil {
		return fmt.Errorf("error getting STH from log: %s", err)
	}
	newHead, entries, err := ic.getEntries(current, int64(sth.TreeSize))
	if err != nil {
		return fmt.Errorf("error retrieving entries from log: %s", err)
	}

	err = ic.checkEntries(certs, entries)
	if err != nil {
		return fmt.Errorf("error checking retrieved entries: %s", err)
	}

	err = ic.db.UpdateIndex(ic.logID, newHead)
	if err != nil {
		return fmt.Errorf("error updating current log index: %s", err)
	}

	return nil
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
			err = ic.db.MarkCertSeen(matching.ID, ic.clk.Now())
			if err != nil {
				return fmt.Errorf("error marking certificate as seen: %s", err)
			}
			delete(lookup, fmt.Sprintf("%x", h))
		}
	}

	var oldest float64
	for _, unseen := range lookup {
		if oldest == 0 || time.Since(unseen.Timestamp).Seconds() > oldest {
			oldest = time.Since(unseen.Timestamp).Seconds()
		}
	}
	oldestUnseen.Set(oldest)

	return nil
}
