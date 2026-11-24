package cryptobrokerclientgo

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func privateKeyDER(key []byte) ([]byte, error) {
	if _, err := x509.ParsePKCS8PrivateKey(key); err != nil {
		return nil, fmt.Errorf("private key must be PKCS#8 DER: %w", err)
	}
	return key, nil
}

func publicKeyDER(key []byte) ([]byte, error) {
	if block, rest := pem.Decode(key); block != nil {
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("public key PEM contains trailing data")
		}

		switch block.Type {
		case "ML-DSA PUBLIC KEY":
			return block.Bytes, nil
		case "CERTIFICATE":
			key = block.Bytes
		case "PUBLIC KEY", "RSA PUBLIC KEY":
			key = block.Bytes
		default:
			return nil, fmt.Errorf("unsupported public key PEM block type %q", block.Type)
		}
	}

	if certificate, err := x509.ParseCertificate(key); err == nil {
		return x509.MarshalPKIXPublicKey(certificate.PublicKey)
	}

	publicKey, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		publicKey, err = x509.ParsePKCS1PublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("public key must be PEM or supported DER: %w", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key as DER: %w", err)
	}

	return der, nil
}
