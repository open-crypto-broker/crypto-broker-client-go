package cryptobrokerclientgo

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

func privateKeyDER(key []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(key)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return key, nil
	}

	if bytes.Count(trimmed, []byte("-----BEGIN")) != 1 {
		return nil, fmt.Errorf("private key must be a single PKCS#8 PEM block")
	}

	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("private key must be a single valid PKCS#8 PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("private key PEM must use the PRIVATE KEY label; convert the key to unencrypted PKCS#8")
	}

	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("private key PKCS#8 PEM block must not contain headers")
	}

	return block.Bytes, nil
}

func publicKeyDER(key []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(key)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return key, nil
	}

	if bytes.Count(trimmed, []byte("-----BEGIN")) != 1 {
		return nil, fmt.Errorf("public key must be a single SubjectPublicKeyInfo PEM block")
	}

	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("public key must be a single valid SubjectPublicKeyInfo PEM block")
	}
	
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("public key PEM must use the PUBLIC KEY label")
	}

	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("public key PEM block must not contain headers")
	}

	return block.Bytes, nil
}
