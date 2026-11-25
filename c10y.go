package cryptobrokerclientgo

import (
	"bytes"
	"fmt"
)

func privateKeyDER(key []byte) ([]byte, error) {
	return requireDERKey(key, "PKCS#8 private key")
}

func publicKeyDER(key []byte) ([]byte, error) {
	return requireDERKey(key, "SubjectPublicKeyInfo public key")
}

func requireDERKey(key []byte, expected string) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN")) {
		return nil, fmt.Errorf("%s must be DER encoded; PEM is not supported", expected)
	}
	return key, nil
}
