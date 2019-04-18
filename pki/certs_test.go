package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

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
			ExpectedErr: errNilSubjKey,
		},
		{
			Name:        "nil issuerkey",
			SubjectKey:  testKey,
			ExpectedErr: errNilIssuerKey,
		},
		{
			Name:        "nil issuercert",
			SubjectKey:  testKey,
			IssuerKey:   testKey,
			ExpectedErr: errNilIssuerCert,
		},
		{
			Name:        "nil template",
			SubjectKey:  testKey,
			IssuerKey:   testKey,
			IssuerCert:  testCert,
			ExpectedErr: errNilTemplate,
		},
		{
			Name:        "nil template",
			SubjectKey:  testKey,
			IssuerKey:   testKey,
			IssuerCert:  testCert,
			ExpectedErr: errNilTemplate,
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
	clk := clock.New()

	certPair, err := IssueTestCertificate(issuerKey, issuerCert, clk, nil, nil)
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
		t.Errorf("PreCert was missing expected CT Poison Extension ID")
	}
	if findCTPoison(certPair.Cert) {
		t.Errorf("Cert had unexpected CT Poison Extension ID")
	}
}

func TestIssueTestCertificateWindow(t *testing.T) {
	issuerKey, _ := RandKey()
	issuerCert := &x509.Certificate{}

	windowStart, _ := time.Parse(time.RFC3339, "2000-01-01T00:00:00Z")
	windowEnd, _ := time.Parse(time.RFC3339, "2001-01-01T00:00:00Z")

	shortFormat := func(t time.Time) string {
		return t.Format("2006-01-02")
	}

	testCases := []struct {
		now, notBefore, notAfter string
	}{
		{now: "1995-05-05", notBefore: "1995-05-05", notAfter: "2000-12-31"},
		{now: "2000-03-03", notBefore: "2000-03-03", notAfter: "2000-12-31"},
		{now: "2000-12-12", notBefore: "2000-12-12", notAfter: "2000-12-31"},
		{now: "2019-04-17", notBefore: "2000-10-02", notAfter: "2000-12-31"},
	}

	for _, tc := range testCases {
		t.Run(tc.now, func(t *testing.T) {
			now, err := time.Parse("2006-01-02", tc.now)
			if err != nil {
				t.Fatalf("Parsing %q: %s", tc.now, err)
			}
			clk := clock.NewFake()
			clk.Set(now)

			// Issue a cert pair with specific WindowStart and WindowEnd
			certPair, err := IssueTestCertificate(issuerKey, issuerCert, clk, &windowStart, &windowEnd)
			if err != nil {
				t.Fatalf("unexpected error from IssueTestCertificate: %s", err.Error())
			}

			if certPair.PreCert == nil {
				t.Fatalf("unexpected nil PreCert in CertPair returned from IssueTestCertificate")
			}

			if certPair.Cert == nil {
				t.Fatalf("unexpected nil Cert in CertPair returned from IssueTestCertificate")
			}

			// Check the precert notbefore/notafter match expected
			notBefore := shortFormat(certPair.PreCert.NotBefore)
			notAfter := shortFormat(certPair.PreCert.NotAfter)
			if notBefore != tc.notBefore {
				t.Errorf("preCert notBefore was %q, expected %q",
					notBefore, tc.notBefore)
			}
			if notAfter != tc.notAfter {
				t.Errorf("preCert notAfter was %q, expected %q",
					notAfter, tc.notAfter)
			}
			// Check that the cert notbefore/notafter match expected
			notBefore = shortFormat(certPair.Cert.NotBefore)
			notAfter = shortFormat(certPair.Cert.NotAfter)
			if notBefore != tc.notBefore {
				t.Errorf("cert notBefore was %q, expected %q",
					notBefore, tc.notBefore)
			}
			if notAfter != tc.notAfter {
				t.Errorf("cert notAfter was %q, expected %q",
					notAfter, tc.notAfter)
			}
		})
	}
}

func TestIssueTestCertificateNoWindow(t *testing.T) {
	issuerKey, _ := RandKey()
	issuerCert := &x509.Certificate{}
	clk := clock.New()

	// Issue a cert pair with nil WindowStart and WindowEnd
	certPair, err := IssueTestCertificate(issuerKey, issuerCert, clk, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error from IssueTestCertificate: %s", err.Error())
	}

	if certPair.PreCert == nil {
		t.Fatalf("unexpected nil PreCert in CertPair returned from IssueTestCertificate")
	}

	if certPair.Cert == nil {
		t.Fatalf("unexpected nil Cert in CertPair returned from IssueTestCertificate")
	}

	shortFormat := func(t time.Time) string {
		return t.Format("2006-01-02")
	}

	// Check that the precert notbefore/notafter match defaults
	now := shortFormat(clk.Now())
	defaultNotAfter := shortFormat(clk.Now().AddDate(0, 0, 90))
	notBefore := shortFormat(certPair.PreCert.NotBefore)
	notAfter := shortFormat(certPair.PreCert.NotAfter)
	if notBefore != now {
		t.Errorf("preCert notBefore was %q, expected %q",
			notBefore, now)
	}
	if notAfter != defaultNotAfter {
		t.Errorf("preCert notAfter was %q, expected %q",
			notAfter, defaultNotAfter)
	}

	// Check that the cert notbefore/notafter match defaults
	notBefore = shortFormat(certPair.Cert.NotBefore)
	notAfter = shortFormat(certPair.Cert.NotAfter)
	if notBefore != now {
		t.Errorf("cert notBefore was %q, expected %q",
			notBefore, now)
	}
	if notAfter != defaultNotAfter {
		t.Errorf("cert notAfter was %q, expected %q",
			notAfter, defaultNotAfter)
	}
}
