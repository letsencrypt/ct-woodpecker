package pki

import (
	"testing"

	"github.com/letsencrypt/ct-woodpecker/test"
)

func TestLoadPrivateKey(t *testing.T) {
	badB64 := `#$*$(`
	badB64File := test.WriteTemp(t, badB64, "bad.b64")

	// echo -n "lol keys" | base64
	badKeyBytes := "bG9sIGtleXM="
	badKeyFile := test.WriteTemp(t, badKeyBytes, "bad.key")

	testCases := []struct {
		Name        string
		Path        string
		ExpectError bool
	}{
		{
			Name:        "Invalid file path",
			Path:        "whatever.this.doesnt.even.exist.pem",
			ExpectError: true,
		},
		{
			Name:        "Invalid base64",
			Path:        badB64File,
			ExpectError: true,
		},
		{
			Name:        "Invalid key",
			Path:        badKeyFile,
			ExpectError: true,
		},
		{
			Name:        "Good key",
			Path:        "../test/issuer.key",
			ExpectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := LoadPrivateKey(tc.Path)
			if err != nil && !tc.ExpectError {
				t.Errorf("Unexpected error: %s", err.Error())
			} else if err == nil && tc.ExpectError {
				t.Error("Expected error, got none")
			}
		})
	}
}

func TestLoadCertificate(t *testing.T) {
	noPEMFile := test.WriteTemp(t, "", "no.blocks.pem")

	wrongPEM := `
-----BEGIN GARBAGE-----
bG9sIGtleXM=
-----END GARBAGE-----
`
	wrongPEMFile := test.WriteTemp(t, wrongPEM, "wrong.type.pem")

	extraBytes := wrongPEM + "!!bonus bytes!!"
	extraBytesFile := test.WriteTemp(t, extraBytes, "extra.bytes.pem")

	testCases := []struct {
		Name        string
		Path        string
		ExpectError bool
	}{
		{
			Name:        "Invalid file path",
			Path:        "whatever.this.doesnt.even.exist.pem",
			ExpectError: true,
		},
		{
			Name:        "No PEM blocks",
			Path:        noPEMFile,
			ExpectError: true,
		},
		{
			Name:        "Extra PEM bytes",
			Path:        extraBytesFile,
			ExpectError: true,
		},
		{
			Name:        "Wrong PEM block type",
			Path:        wrongPEMFile,
			ExpectError: true,
		},
		{
			Name:        "Valid PEM certificate",
			Path:        "../test/issuer.pem",
			ExpectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := LoadCertificate(tc.Path)
			if err != nil && !tc.ExpectError {
				t.Errorf("Unexpected error: %s", err.Error())
			} else if err == nil && tc.ExpectError {
				t.Error("Expected error, got none")
			}
		})
	}
}
