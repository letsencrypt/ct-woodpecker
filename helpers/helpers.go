package helpers

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func LoadPrivateKey(file string) (*ecdsa.PrivateKey, error) {
	if encodedKeyBytes, err := ioutil.ReadFile(file); err != nil {
		return nil, err
	} else if keyBytes, err := base64.StdEncoding.DecodeString(string(encodedKeyBytes)); err != nil {
		return nil, err
	} else if key, err := x509.ParseECPrivateKey(keyBytes); err != nil {
		return nil, err
	} else {
		return key, nil
	}
}

func LoadCertificate(file string) (*x509.Certificate, error) {
	if pemBytes, err := ioutil.ReadFile(file); err != nil {
		return nil, err
	} else if certBlock, rest := pem.Decode(pemBytes); len(rest) != 0 {
		return nil, fmt.Errorf("%q contained %d extra bytes after PEM decoding",
			file, len(rest))
	} else if certBlock == nil {
		return nil, fmt.Errorf("%q contained no PEM blocks", file)
	} else if certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%q contained a PEM block with type %q, not CERTIFICATE", file, certBlock.Type)
	} else if cert, err := x509.ParseCertificate(certBlock.Bytes); err != nil {
		return nil, err
	} else {
		return cert, nil
	}
}
