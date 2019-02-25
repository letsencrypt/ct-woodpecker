package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/letsencrypt/ct-woodpecker/pki"
)

func main() {
	issuerKey, err := pki.RandKey()
	if err != nil {
		log.Fatalf("Unable to generate random issuer key: %s\n", err.Error())
	}

	keyBytes, err := x509.MarshalECPrivateKey(issuerKey)
	if err != nil {
		log.Fatalf("Unable to encode issuer key to DER: %s\n", err.Error())
	}

	encodedBytes := base64.StdEncoding.EncodeToString(keyBytes)
	fmt.Printf("Key:\n%s\n", encodedBytes)

	serial, err := pki.RandSerial()
	if err != nil {
		log.Fatalf("Unable to generate random issuer certificate serial: %s\n", err.Error())
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "ct-woodpecker CA" + hex.EncodeToString(serial.Bytes()[:3]),
		},
		SerialNumber:          serial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := pki.IssueCertificate(issuerKey.Public(), issuerKey, template, template)
	if err != nil {
		log.Fatalf("Unable to create self-signed issuer cert: %s\n", err.Error())
	}

	var pemBuffer bytes.Buffer
	_ = pem.Encode(&pemBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fmt.Printf("\nCert:\n%s\n", pemBuffer.String())
}
