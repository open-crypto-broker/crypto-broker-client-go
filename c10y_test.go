package cryptobrokerclientgo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestKeyEncoding(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	gotPrivateDER, err := privateKeyDER(privatePEM)
	if err != nil || !bytes.Equal(gotPrivateDER, privateDER) {
		t.Fatalf("privateKeyDER(PEM) = %x, err %v; want %x", gotPrivateDER, err, privateDER)
	}
	gotPrivateDER, err = privateKeyDER(privateDER)
	if err != nil || !bytes.Equal(gotPrivateDER, privateDER) {
		t.Fatalf("privateKeyDER(DER) = %x, err %v; want %x", gotPrivateDER, err, privateDER)
	}

	gotPublicDER, err := publicKeyDER(publicPEM)
	if err != nil || !bytes.Equal(gotPublicDER, publicDER) {
		t.Fatalf("publicKeyDER(PEM) = %x, err %v; want %x", gotPublicDER, err, publicDER)
	}
	gotPublicDER, err = publicKeyDER(publicDER)
	if err != nil || !bytes.Equal(gotPublicDER, publicDER) {
		t.Fatalf("publicKeyDER(DER) = %x, err %v; want %x", gotPublicDER, err, publicDER)
	}
}

func TestKeyEncodingRejectsInvalidInput(t *testing.T) {
	if _, err := privateKeyDER([]byte("not a key")); err == nil {
		t.Fatal("privateKeyDER() accepted invalid key")
	}
	if _, err := publicKeyDER([]byte("not a key")); err == nil {
		t.Fatal("publicKeyDER() accepted invalid key")
	}

	mlDSAKey := []byte{1, 2, 3}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "ML-DSA PRIVATE KEY", Bytes: mlDSAKey})
	got, err := privateKeyDER(encoded)
	if err != nil || !bytes.Equal(got, mlDSAKey) {
		t.Fatalf("privateKeyDER(ML-DSA PEM) = %x, err %v; want %x", got, err, mlDSAKey)
	}
}

func testSigningKeyMaterial(t *testing.T) (privateDER, privatePEM, publicDER, publicPEM []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privateDER, privatePEM, publicDER, publicPEM
}
