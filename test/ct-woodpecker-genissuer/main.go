package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"time"
)

func main() {
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyBytes, _ := x509.MarshalECPrivateKey(issuerKey)
	encodedBytes := base64.StdEncoding.EncodeToString(keyBytes)
	fmt.Printf("Key:\n%s\n", encodedBytes)

	serial, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))

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
		IsCA: true,
	}

	der, _ := x509.CreateCertificate(rand.Reader, template, template, issuerKey.Public(), issuerKey)

	var pemBuffer bytes.Buffer
	_ = pem.Encode(&pemBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	fmt.Printf("\nCert:\n%s\n", pemBuffer.String())
}
