package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math"
	"math/big"

	"github.com/jmhodges/clock"
)

const (
	// Prefix for the subject common name of certificates generated for submission
	// to logs
	subjCNPrefix = "ct-woodpecker "
)

// RandSerial generates a random *bigInt to use as a certificate serial or
// returns an error.
func RandSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	return serial, nil
}

// RandKey generates a random ECDSA private key or returns an error.
func RandKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// IssueCertificate uses the monitor's certIssuer and certIssuerKey to generate
// a leaf-certificate that can be submitted to a log. The certificate's subject
// common name will be the monitor's subjCNPrefix and the first three bytes of
// the random serial number encoded in hex.
// TODO(@cpu) Write this comment

func IssueCertificate(
	subjectKey crypto.PublicKey,
	issuerKey *ecdsa.PrivateKey,
	issuerCert, template *x509.Certificate) (*x509.Certificate, error) {
	if subjectKey == nil {
		return nil, errors.New("cannot IssueCertificate with nil subjectKey")
	}
	if issuerKey == nil {
		return nil, errors.New("cannot IssueCertificate with nil issuerKey")
	}
	if issuerCert == nil {
		return nil, errors.New("cannot IssueCertificate with nil issuerCert")
	}
	if template == nil {
		return nil, errors.New("cannot IssueCertificate with nil template")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, subjectKey, issuerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func IssueTestCertificate(
	issuerKey *ecdsa.PrivateKey,
	issuerCert *x509.Certificate,
	clk clock.Clock) (*x509.Certificate, error) {

	certKey, err := RandKey()
	if err != nil {
		return nil, err
	}
	serial, err := RandSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: subjCNPrefix + hex.EncodeToString(serial.Bytes()[:3]),
		},
		SerialNumber:          serial,
		NotBefore:             clk.Now(),
		NotAfter:              clk.Now().AddDate(0, 0, 90),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}

	return IssueCertificate(certKey.Public(), issuerKey, issuerCert, template)
}
