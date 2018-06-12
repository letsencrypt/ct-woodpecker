// Package pki provides helpers for creating random certificate serial numbers,
// random private keys, and issuing test certificates.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math"
	"math/big"

	"github.com/jmhodges/clock"
)

const (
	// Domain suffix for the subject common name of certificates generated for submission
	// to logs. The prefix will be generated randomly from the certificate serial number.
	testCertDomain = ".woodpecker.testing.letsencrypt.org"
)

var (
	nilSubjKeyErr    = errors.New("cannot IssueCertificate with nil subjectKey")
	nilIssuerKeyErr  = errors.New("cannot IssueCertificate with nil issuerKey")
	nilIssuerCertErr = errors.New("cannot IssueCertificate with nil issuerCert")
	nilTemplateErr   = errors.New("cannot IssueCertificate with nil template")

	ctPoisonExtensionID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	ctPoisonExtension   = pkix.Extension{
		// OIDExtensionCTPoison is defined in RFC 6962 s3.1.
		Id:       ctPoisonExtensionID,
		Critical: true,
		// ASN.1 DER NULL, Hex encoded.
		Value: []byte{0x05, 0x00},
	}
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

// IssueCertificate uses the provided issuerKey and issuerCert to issue a new
// X509 Certificate with the provided subjectKey based on the provided template.
func IssueCertificate(
	subjectKey crypto.PublicKey,
	issuerKey *ecdsa.PrivateKey,
	issuerCert, template *x509.Certificate) (*x509.Certificate, error) {
	if subjectKey == nil {
		return nil, nilSubjKeyErr
	}
	if issuerKey == nil {
		return nil, nilIssuerKeyErr
	}
	if issuerCert == nil {
		return nil, nilIssuerCertErr
	}
	if template == nil {
		return nil, nilTemplateErr
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

// CertificatePair is a struct for holding a precertificate and a matching final
// certificate.
type CertificatePair struct {
	PreCert *x509.Certificate
	Cert    *x509.Certificate
}

// IssueTestCertificate uses the monitor's certIssuer and certIssuerKey to generate
// a precertificate and a matching final leaf-certificate that can be submitted
// to a log.The certificate's subject common name will be a random subdomain
// based on the certificate serial under the `testCertDomain` domain. This
// function creates certificates that will be submitted to public logs and so
// while they are not issued by a trusted root  we try to avoid cablint errors
// to avoid requiring log monitors special-case our submissions.
func IssueTestCertificate(
	issuerKey *ecdsa.PrivateKey,
	issuerCert *x509.Certificate,
	clk clock.Clock) (CertificatePair, error) {

	certKey, err := RandKey()
	if err != nil {
		return CertificatePair{}, err
	}
	serial, err := RandSerial()
	if err != nil {
		return CertificatePair{}, err
	}

	domain := hex.EncodeToString(serial.Bytes()[:5]) + testCertDomain

	issueLeafCert := func(precert bool) (*x509.Certificate, error) {
		tmpl := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: domain,
			},
			DNSNames:              []string{domain},
			SerialNumber:          serial,
			NotBefore:             clk.Now(),
			NotAfter:              clk.Now().AddDate(0, 0, 90),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA: false,
			IssuingCertificateURL: []string{"http://issuer" + testCertDomain},
			CRLDistributionPoints: []string{"http://crls" + testCertDomain},
		}
		if precert {
			tmpl.ExtraExtensions = []pkix.Extension{ctPoisonExtension}
		}
		return IssueCertificate(certKey.Public(), issuerKey, issuerCert, tmpl)
	}

	preCert, err := issueLeafCert(true)
	if err != nil {
		return CertificatePair{}, err
	}
	cert, err := issueLeafCert(false)
	if err != nil {
		return CertificatePair{}, err
	}

	return CertificatePair{
		PreCert: preCert,
		Cert:    cert,
	}, nil
}
