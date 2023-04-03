package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"strings"
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

	certPair, err := IssueTestCertificate("", issuerKey, issuerCert, clk, nil, nil)
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

	expectedDomain := hex.EncodeToString(certPair.PreCert.SerialNumber.Bytes()[:5]) + defaultTestCertDomain
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

	expectedIssuerURL := "http://issuer" + defaultTestCertDomain
	if len(certPair.PreCert.IssuingCertificateURL) != 1 || certPair.PreCert.IssuingCertificateURL[0] != expectedIssuerURL {
		t.Errorf("PreCert had wrong IssuingCertificateURL. Expected [%q], found %#v", expectedIssuerURL, certPair.PreCert.IssuingCertificateURL)
	}
	if len(certPair.Cert.IssuingCertificateURL) != 1 || certPair.Cert.IssuingCertificateURL[0] != expectedIssuerURL {
		t.Errorf("Cert had wrong IssuingCertificateURL. Expected [%q], found %#v", expectedIssuerURL, certPair.Cert.IssuingCertificateURL)
	}

	expectedCRLURL := "http://crls" + defaultTestCertDomain
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

func TestIssueTestCertificateWindowNil(t *testing.T) {
	issuerKey, _ := RandKey()
	issuerCert := &x509.Certificate{}
	clk := clock.New()

	// Issue a cert pair with nil WindowStart and WindowEnd
	certPair, err := IssueTestCertificate("", issuerKey, issuerCert, clk, nil, nil)
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
		return t.Format("2006-01-02 15:04")
	}

	// Check that the precert notbefore/notafter match defaults
	now := shortFormat(clk.Now().UTC())
	validityPeriod := 90*24*time.Hour - time.Second
	defaultNotAfter := shortFormat(clk.Now().UTC().Add(validityPeriod))
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

// TestIssueTestCertificateWindowNotNil tests cases where the certificate
// is being generated for temporal shards and ensures the certificates are
// generated within the temporal window.
func TestIssueTestCertificateWindowNotNil(t *testing.T) {
	issuerKey, _ := RandKey()
	issuerCert := &x509.Certificate{}
	clk := clock.New()
	validityPeriod := 90*24*time.Hour - time.Second

	// set window for a shard that is in its active temporal window
	currentWindowStart := clk.Now().AddDate(0, 0, -30)
	currentWindowEnd := clk.Now().AddDate(0, 0, 180)

	// set window for a shard that is in the past
	pastWindowStart, _ := time.Parse(time.RFC3339, "2000-01-01T00:00:00Z")
	pastWindowEnd, _ := time.Parse(time.RFC3339, "2001-01-01T00:00:00Z")

	// set window for a shard that is in the future
	futureWindowStart, _ := time.Parse(time.RFC3339, "2100-01-01T00:00:00Z")
	futureWindowEnd, _ := time.Parse(time.RFC3339, "2101-01-01T00:00:00Z")

	type testCase struct {
		name        string
		windowStart time.Time
		windowEnd   time.Time
	}
	testCases := []testCase{
		{
			name:        "current temporal shard",
			windowStart: currentWindowStart,
			windowEnd:   currentWindowEnd,
		},
		{
			name:        "past temporal shard",
			windowStart: pastWindowStart,
			windowEnd:   pastWindowEnd,
		},
		{
			name:        "future temporal shard",
			windowStart: futureWindowStart,
			windowEnd:   futureWindowEnd,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Issue a cert pair with specific WindowStart and WindowEnd
			certPair, err := IssueTestCertificate("", issuerKey, issuerCert, clk, &tc.windowStart, &tc.windowEnd)
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
				return t.Format("2006-01-02 15:04:05")
			}

			// Check the precert notbefore/notafter match expected
			notAfter := shortFormat(certPair.PreCert.NotAfter)
			expectedNotAfter := shortFormat(certPair.PreCert.NotBefore.Add(validityPeriod))
			if notAfter != expectedNotAfter {
				t.Errorf("preCert notAfter was %q, expected %q",
					notAfter, expectedNotAfter)
			}
			if certPair.PreCert.NotAfter.Before(tc.windowStart) || certPair.PreCert.NotAfter.After(tc.windowEnd) {
				t.Errorf("preCert notAfter was %q, expected to be between %q and %q",
					notAfter, tc.windowStart, tc.windowEnd)
			}

			// Check that the cert notbefore/notafter match expected
			notAfter = shortFormat(certPair.Cert.NotAfter)
			expectedNotAfter = shortFormat(certPair.Cert.NotBefore.Add(validityPeriod))
			if notAfter != expectedNotAfter {
				t.Errorf("Cert notAfter was %q, expected %q",
					notAfter, expectedNotAfter)
			}
			if certPair.Cert.NotAfter.Before(tc.windowStart) || certPair.Cert.NotAfter.After(tc.windowEnd) {
				t.Errorf("cert notAfter was %q, expected to be between %q and %q",
					notAfter, tc.windowStart, tc.windowEnd)
			}
		})
	}
}

func TestIssueTestCertificateBaseDomain(t *testing.T) {
	issuerKey, _ := RandKey()
	issuerCert := &x509.Certificate{}
	clk := clock.New()

	testCases := []struct {
		name        string
		baseName    string
		expectedErr string
	}{
		{
			name:        "invalid base name",
			baseName:    "example.com",
			expectedErr: "baseDomain must start with '.' to be used as a domain prefix",
		},
		{
			name: "default base name",
		},
		{
			name:     "custom base name",
			baseName: ".custom.example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certPair, err := IssueTestCertificate(tc.baseName, issuerKey, issuerCert, clk, nil, nil)

			if tc.expectedErr == "" && err != nil {
				t.Errorf("unexpected error from IssueTestCertificate: %s", err.Error())
			} else if tc.expectedErr != "" && err == nil {
				t.Errorf("expected err %q got nil", tc.expectedErr)
			} else if tc.expectedErr != "" && err != nil {
				if actual := err.Error(); actual != tc.expectedErr {
					t.Errorf("expected err %q got %q", tc.expectedErr, actual)
				}
			} else {
				expected := tc.baseName
				if expected == "" {
					expected = defaultTestCertDomain
				}
				if certPair.Cert == nil {
					t.Fatalf("unexpected nil Cert in CertPair returned from IssueTestCertificate")
				}
				if !strings.HasSuffix(certPair.Cert.Subject.CommonName, expected) {
					t.Errorf("expected cert to have subj. CN suffix %q, was %q", expected, certPair.Cert.Subject.CommonName)
				}
			}
		})
	}
}
