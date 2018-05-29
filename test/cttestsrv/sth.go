package cttestsrv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
)

func signSTH(signer *ecdsa.PrivateKey, sth *ct.SignedTreeHead) error {
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(sthBytes)
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(signer.Public()),
		},
		Signature: signature,
	}

	return nil
}
