package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/jmhodges/clock"
)

func TestIssueCertificate(t *testing.T) {
	testKey, _ := RandKey()
	testCert := &x509.Certificate{}

	testCases := []struct {
		Name        string
		SubjectKey  crypto.PublicKey
		IssuerKey   *ecdsa.PrivateKey
		IssuerCert  *x509.Certificate
		Template    *x509.Certificate
		ExpectedErr error
	}{
		{
			Name:        "nil subjectkey",
			ExpectedErr: nilSubjKeyErr,
		},
		{
			Name:        "nil issuerkey",
			SubjectKey:  testKey,
			ExpectedErr: nilIssuerKeyErr,
		},
		{
			Name:        "nil issuercert",
			SubjectKey:  testKey,
			IssuerKey:   testKey,
			ExpectedErr: nilIssuerCertErr,
		},
		{
			Name:        "nil template",
			SubjectKey:  testKey,
			IssuerKey:   testKey,
			IssuerCert:  testCert,
			ExpectedErr: nilTemplateErr,
		},
		{
			Name:        "nil template",
			SubjectKey:  testKey,
			IssuerKey:   testKey,
			IssuerCert:  testCert,
			ExpectedErr: nilTemplateErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := IssueCertificate(tc.SubjectKey, tc.IssuerKey, tc.IssuerCert, tc.Template)
			if err != tc.ExpectedErr {
				t.Errorf("expected error %#v, got %#v\n", tc.ExpectedErr, err)
			}
		})
	}
}

func TestIssueTestCertificate(t *testing.T) {
	issuerKey, _ := RandKey()
	issuerCert := &x509.Certificate{}
	clk := clock.Default()

	certPair, err := IssueTestCertificate(issuerKey, issuerCert, clk)
	if err != nil {
		t.Fatalf("unexpected error from IssueTestCertificate: %s", err.Error())
	}

	if certPair.PreCert == nil {
		t.Fatalf("unexpected nil PreCert in CertPair returned from IssueTestCertificate")
	}

	if certPair.Cert == nil {
		t.Fatalf("unexpected nil Cert in CertPair returned from IssueTestCertificate")
	}

	if certPair.PreCert.SerialNumber == nil {
		t.Fatalf("unexpected nil SerialNumber in CertPair.PreCert")
	}

	if certPair.Cert.SerialNumber == nil {
		t.Fatalf("unexpected nil SerialNumber in CertPair.Cert")
	}

	if certPair.PreCert.SerialNumber.Cmp(certPair.Cert.SerialNumber) != 0 {
		t.Errorf("SerialNumbers of CertPair did not match")
	}

	expectedDomain := hex.EncodeToString(certPair.PreCert.SerialNumber.Bytes()[:5]) + testCertDomain
	if certPair.PreCert.Subject.CommonName != expectedDomain {
		t.Errorf("PreCert had wrong CommonName. Expected %q, had %q",
			expectedDomain, certPair.PreCert.Subject.CommonName)
	}
	if certPair.PreCert.Subject.CommonName != certPair.Cert.Subject.CommonName {
		t.Errorf("Cert had different CommonName from PreCert. Expected %q, had %q",
			expectedDomain, certPair.Cert.Subject.CommonName)
	}

	if len(certPair.PreCert.DNSNames) != 1 || certPair.PreCert.DNSNames[0] != expectedDomain {
		t.Errorf("PreCert had wrong DNSNames. Expected [%q], found %#v", expectedDomain, certPair.PreCert.DNSNames)
	}
	if len(certPair.Cert.DNSNames) != 1 || certPair.Cert.DNSNames[0] != expectedDomain {
		t.Errorf("Cert had wrong DNSNames. Expected [%q], found %#v", expectedDomain, certPair.Cert.DNSNames)
	}

	if certPair.PreCert.IsCA {
		t.Errorf("PreCert was unexpectedly a CA")
	}
	if certPair.Cert.IsCA {
		t.Errorf("Cert was unexpectedly a CA")
	}
	if !certPair.PreCert.BasicConstraintsValid {
		t.Errorf("PreCert was not BasicConstraintsValid")
	}
	if !certPair.Cert.BasicConstraintsValid {
		t.Errorf("Cert was not BasicConstraintsValid")
	}

	if certPair.PreCert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("PreCert had wrong KeyUsage. Expected %#v, found %#v", x509.KeyUsageDigitalSignature, certPair.PreCert.KeyUsage)
	}
	if certPair.Cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("Cert had wrong KeyUsage. Expected %#v, found %#v", x509.KeyUsageDigitalSignature, certPair.Cert.KeyUsage)
	}

	expectedIssuerURL := "http://issuer" + testCertDomain
	if len(certPair.PreCert.IssuingCertificateURL) != 1 || certPair.PreCert.IssuingCertificateURL[0] != expectedIssuerURL {
		t.Errorf("PreCert had wrong IssuingCertificateURL. Expected [%q], found %#v", expectedIssuerURL, certPair.PreCert.IssuingCertificateURL)
	}
	if len(certPair.Cert.IssuingCertificateURL) != 1 || certPair.Cert.IssuingCertificateURL[0] != expectedIssuerURL {
		t.Errorf("Cert had wrong IssuingCertificateURL. Expected [%q], found %#v", expectedIssuerURL, certPair.Cert.IssuingCertificateURL)
	}

	expectedCRLURL := "http://crls" + testCertDomain
	if len(certPair.PreCert.CRLDistributionPoints) != 1 || certPair.PreCert.CRLDistributionPoints[0] != expectedCRLURL {
		t.Errorf("PreCert had wrong CRLDistributionPoints. Expected [%q], found %#v", expectedCRLURL, certPair.PreCert.CRLDistributionPoints)
	}
	if len(certPair.Cert.IssuingCertificateURL) != 1 || certPair.Cert.IssuingCertificateURL[0] != expectedIssuerURL {
		t.Errorf("Cert had wrong CRLDistributionPoints. Expected [%q], found %#v", expectedCRLURL, certPair.Cert.CRLDistributionPoints)
	}

	findCTPoison := func(cert *x509.Certificate) bool {
		foundPoison := false
		for _, extension := range cert.Extensions {
			if extension.Id.Equal(ctPoisonExtensionID) {
				foundPoison = true
			}
		}
		return foundPoison
	}
	if !findCTPoison(certPair.PreCert) {
		t.Errorf("PreCert was missing expected CT Poision Extension ID")
	}
	if findCTPoison(certPair.Cert) {
		t.Errorf("Cert had unexpected CT Poision Extension ID")
	}
}
