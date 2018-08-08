package monitor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/letsencrypt/ct-woodpecker/storage"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var oldestUnseen = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "oldest_unincorporated_cert",
	Help: "Number of seconds since the oldest SCT that we haven't matched to a log entry was received",
})

var unseenCount = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "unincorporated_certs",
	Help: "Number of SCTs that haven't been matched to log entries",
})

var inclusionErrors = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "inclusion_checker_errors",
	Help: "Number of errors encountered while attempting to check for certificate inclusion",
}, []string{"type"})

type InclusionOptions struct {
	Interval       time.Duration
	FetchBatchSize int64
	MaxGetEntries  int64
	StartIndex     int64
}

type inclusionClient interface {
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error)
}

type inclusionChecker struct {
	monitorCheck
	client           inclusionClient
	db               storage.Storage
	signatureChecker *ct.SignatureVerifier
	stopChan         chan bool

	interval      time.Duration
	batchSize     int64
	maxGetEntries int64
	startIndex    int64
}

func newInclusionChecker(
	mc monitorCheck,
	opts *InclusionOptions,
	client inclusionClient,
	logKey string,
	storage storage.Storage) (*inclusionChecker, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(logKey)
	if err != nil {
		return nil, err
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return nil, err
	}
	sv, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		return nil, err
	}
	if storage == nil {
		return nil, errors.New("Storage must not be nil")
	}
	if opts.StartIndex < 0 {
		return nil, errors.New("StartIndex must be >= 0")
	}
	current, err := storage.GetIndex(mc.logID)
	if err != nil {
		return nil, fmt.Errorf("error getting current log index %s", err)
	}
	if current < opts.StartIndex {
		err = storage.UpdateIndex(mc.logID, opts.StartIndex)
		if err != nil {
			return nil, fmt.Errorf("error updating current index to start index (%d) : %s",
				opts.StartIndex, err)
		}
	}
	return &inclusionChecker{
		monitorCheck:     mc,
		client:           client,
		db:               storage,
		signatureChecker: sv,
		stopChan:         make(chan bool, 1),
		interval:         opts.Interval,
		batchSize:        opts.FetchBatchSize,
		maxGetEntries:    opts.MaxGetEntries,
		startIndex:       opts.StartIndex,
	}, nil
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
					ic.logErrorf("Checking certificate inclusion failed : %s", err)
				}
			}
		}
	}()
}

func (ic *inclusionChecker) stop() {
	ic.log("Stopping")
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
	unseenCount.Set(float64(len(certs)))
	if len(certs) == 0 {
		// nothing to do, don't advance the index
		return nil
	}

	sth, err := ic.client.GetSTH(context.Background())
	if err != nil {
		inclusionErrors.WithLabelValues("getSTH").Inc()
		return fmt.Errorf("error getting STH from %q: %s", ic.logURI, err)
	}
	newHead, entries, err := ic.getEntries(current, int64(sth.TreeSize)-1)
	if err != nil {
		inclusionErrors.WithLabelValues("getEntries").Inc()
		return fmt.Errorf("error retrieving entries from %q: %s", ic.logURI, err)
	}

	err = ic.checkEntries(certs, entries)
	if err != nil {
		inclusionErrors.WithLabelValues("checkEntries").Inc()
		return fmt.Errorf("error checking retrieved entries for %q: %s", ic.logURI, err)
	}

	ic.logf("Updating inclusion index to %d", newHead)
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
	ic.logf("Getting entries from %d to %d", start, end)
	var allEntries []ct.LogEntry
	for start < end {
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

func mapKey(cert []byte, timestamp uint64) [32]byte {
	content := make([]byte, len(cert)+binary.MaxVarintLen64)
	copy(content, cert)
	binary.PutUvarint(content[len(cert):], timestamp)
	return sha256.Sum256(content)
}

func (ic *inclusionChecker) checkEntries(certs []storage.SubmittedCert, entries []ct.LogEntry) error {
	// Key structure for our lookup map is as follows: SHA256 hash of the certificate
	// body concatenated with the byte encoding of the SCT timestamp. This prevents
	// from having duplicate keys for duplicate submissions with differing SCTs.
	lookup := make(map[[32]byte]storage.SubmittedCert)
	for _, cert := range certs {
		lookup[mapKey(cert.Cert, cert.Timestamp)] = cert
	}
	for _, entry := range entries {
		var certData []byte
		switch entry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			certData = entry.X509Cert.Raw
		case ct.PrecertLogEntryType:
			certData = entry.Precert.Submitted.Data
		}
		h := mapKey(certData, entry.Leaf.TimestampedEntry.Timestamp)
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
