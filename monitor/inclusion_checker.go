package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

var inclusionErrors = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "inclusion_checker_errors",
	Help: "Number of errors encountered while attempting to check for certificate inclusion",
}, []string{"type"})

type InclusionOptions struct {
	Interval       time.Duration
	FetchBatchSize int64
	MaxGetEntries  int64
}

type inclusionClient interface {
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error)
}

type inclusionChecker struct {
	logger           *log.Logger
	client           inclusionClient
	logURI           string
	db               storage.Storage
	signatureChecker *ct.SignatureVerifier
	clk              clock.Clock
	logID            int64
	stopChan         chan bool

	interval      time.Duration
	batchSize     int64
	maxGetEntries int64
}

func (ic *inclusionChecker) run() {
	go func() {
		ticker := time.NewTicker(ic.interval)
		for {
			select {
			case <-ic.stopChan:
				return
			case <-ticker.C:
				err := ic.checkInclusion()
				if err != nil {
					ic.logger.Printf("!!! Checking certificate inclusion failed: %s", err)
				}
			}
		}
	}()
}

func (ic *inclusionChecker) stop() {
	ic.logger.Printf("Stopping %s inclusionChecker", ic.logURI)
	ic.stopChan <- true
}

func (ic *inclusionChecker) checkInclusion() error {
	current, err := ic.db.GetIndex(ic.logID)
	if err != nil {
		inclusionErrors.WithLabelValues("getIndex").Inc()
		return fmt.Errorf("error getting current log index for %q: %s", ic.logURI, err)
	}

	certs, err := ic.db.GetUnseen(ic.logID)
	if err != nil {
		inclusionErrors.WithLabelValues("getUnseen").Inc()
		return fmt.Errorf("error getting unseen certificates from %q: %s", ic.logURI, err)
	}
	if len(certs) == 0 {
		// nothing to do, don't advance the index
		return nil
	}

	sth, err := ic.client.GetSTH(context.Background())
	if err != nil {
		inclusionErrors.WithLabelValues("getSTH").Inc()
		return fmt.Errorf("error getting STH from %q: %s", ic.logURI, err)
	}
	newHead, entries, err := ic.getEntries(current, int64(sth.TreeSize))
	if err != nil {
		inclusionErrors.WithLabelValues("getEntries").Inc()
		return fmt.Errorf("error retrieving entries from %q: %s", ic.logURI, err)
	}

	err = ic.checkEntries(certs, entries)
	if err != nil {
		inclusionErrors.WithLabelValues("checkEntries").Inc()
		return fmt.Errorf("error checking retrieved entries for %q: %s", ic.logURI, err)
	}

	err = ic.db.UpdateIndex(ic.logID, newHead)
	if err != nil {
		inclusionErrors.WithLabelValues("updateIndex").Inc()
		return fmt.Errorf("error updating current index for %q: %s", ic.logURI, err)
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
	if ic.maxGetEntries > 0 && end-start > ic.maxGetEntries {
		end = start + ic.maxGetEntries
	}
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
	// Key structure for our lookup map is as follows: SHA256 hash of the certificate
	// body concatenated with the byte encoding of the SCT timestamp. This prevents
	// from having duplicate keys for duplicate submissions with differing SCTs.
	lookup := make(map[[32]byte]storage.SubmittedCert)
	for _, cert := range certs {
		content := make([]byte, len(cert.Cert)+binary.MaxVarintLen64)
		copy(content, cert.Cert)
		binary.PutUvarint(content[len(cert.Cert):], cert.Timestamp)
		lookup[sha256.Sum256(content)] = cert
	}
	for _, entry := range entries {
		var content []byte
		switch entry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			content = entry.X509Cert.Raw
		case ct.PrecertLogEntryType:
			content = entry.Precert.Submitted.Data
		}
		timestampBuf := make([]byte, binary.MaxVarintLen64)
		binary.PutUvarint(timestampBuf, entry.Leaf.TimestampedEntry.Timestamp)
		content = append(content, timestampBuf...)
		h := sha256.Sum256(content)
		if matching, found := lookup[h]; found {
			var sct ct.SignedCertificateTimestamp
			_, err := tls.Unmarshal(matching.SCT, &sct)
			if err != nil {
				return fmt.Errorf("error unmarshalling SCT: %s", err)
			}
			err = ic.signatureChecker.VerifySCTSignature(sct, entry)
			if err != nil {
				return fmt.Errorf("error verifying SCT signature: %s", err)
			}
			err = ic.db.MarkCertSeen(matching.ID, ic.clk.Now())
			if err != nil {
				return fmt.Errorf("error marking certificate as seen: %s", err)
			}
			delete(lookup, h)
		}
	}

	var oldest uint64
	for _, unseen := range lookup {
		if oldest == 0 || unseen.Timestamp < oldest {
			oldest = unseen.Timestamp
		}
	}
	oldestTime := time.Unix(int64(oldest/1000), 0)
	oldestUnseen.Set(ic.clk.Since(oldestTime).Seconds())

	return nil
}
