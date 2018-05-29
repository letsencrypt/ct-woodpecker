package cttestsrv

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
)

func createTestingSignedSCT(req []string, k *ecdsa.PrivateKey, precert bool, timestamp time.Time) []byte {
	chain := make([]ct.ASN1Cert, len(req))
	for i, certBase64 := range req {
		b, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			panic("cannot decode chain")
		}
		chain[i] = ct.ASN1Cert{Data: b}
	}

	// Generate the internal leaf entry for the SCT
	etype := ct.X509LogEntryType
	if precert {
		etype = ct.PrecertLogEntryType
	}
	leaf, err := ct.MerkleTreeLeafFromRawChain(chain, etype, 0)
	if err != nil {
		panic(fmt.Sprintf("failed to create leaf: %s", err))
	}

	// Sign the SCT
	rawKey, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	logID := sha256.Sum256(rawKey)
	timestampMillis := uint64(timestamp.UnixNano()) / 1e6
	serialized, _ := ct.SerializeSCTSignatureInput(ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  timestampMillis,
	}, ct.LogEntry{Leaf: *leaf})
	hashed := sha256.Sum256(serialized)
	var ecdsaSig struct {
		R, S *big.Int
	}
	ecdsaSig.R, ecdsaSig.S, _ = ecdsa.Sign(rand.Reader, k, hashed[:])
	sig, _ := asn1.Marshal(ecdsaSig)

	// The ct.SignedCertificateTimestamp object doesn't have the needed
	// `json` tags to properly marshal so we need to transform in into
	// a struct that does before we can send it off
	var jsonSCTObj struct {
		SCTVersion ct.Version `json:"sct_version"`
		ID         string     `json:"id"`
		Timestamp  uint64     `json:"timestamp"`
		Extensions string     `json:"extensions"`
		Signature  string     `json:"signature"`
	}
	jsonSCTObj.SCTVersion = ct.V1
	jsonSCTObj.ID = base64.StdEncoding.EncodeToString(logID[:])
	jsonSCTObj.Timestamp = timestampMillis
	ds := ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.ECDSA,
		},
		Signature: sig,
	}
	jsonSCTObj.Signature, _ = ds.Base64String()

	jsonSCT, _ := json.Marshal(jsonSCTObj)
	return jsonSCT
}
