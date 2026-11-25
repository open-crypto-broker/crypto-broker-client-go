package cryptobrokerclientgo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestKeyEncoding(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	gotPrivateDER, err := privateKeyDER(privateDER)
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

}

func TestPrivateKeyDERRejectsLegacyFormats(t *testing.T) {
	privateDER, privatePEM, _, _ := testSigningKeyMaterial(t)
	parsedKey, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected ECDSA key, got %T", parsedKey)
	}
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{"PKCS8 PEM", privatePEM},
		{"PKCS1 DER", x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"SEC1 DER", sec1DER},
		{"SEC1 PEM", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := privateKeyDER(test.key); err == nil {
				t.Fatal("accepted a non-PKCS#8 DER private key")
			}
			client := &mockedGRPCClient{}
			lib := &Library{client: client}
			source := SignKeySource{Single: &KeySource{RawKey: test.key}}
			if _, err := lib.SignData(context.Background(), SignDataPayload{
				Profile: "Default", KeySource: source, Input: []byte("document"),
			}); err == nil {
				t.Fatal("SignData accepted a non-PKCS#8 DER private key")
			}
			if _, err := lib.SignCertificate(context.Background(), SignCertificatePayload{
				Profile: "Default", KeySource: source, CACert: []byte("CA certificate"),
				OutputFormat: OutputFormatDer,
			}); err == nil {
				t.Fatal("SignCertificate accepted a non-PKCS#8 DER private key")
			}
			client.AssertNotCalled(t, "SignData")
			client.AssertNotCalled(t, "SignCertificate")
		})
	}
}

func TestPublicKeyDERRejectsCustomPEMLabels(t *testing.T) {
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{"ML-DSA PUBLIC KEY", pem.EncodeToMemory(&pem.Block{Type: "ML-DSA PUBLIC KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}})},
		{"ML-DSA PRIVATE KEY", pem.EncodeToMemory(&pem.Block{Type: "ML-DSA PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}})},
		{"EC PRIVATE KEY", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}})},
		{"RSA PUBLIC KEY", pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := publicKeyDER(test.key); err == nil {
				t.Fatal("accepted custom PEM label")
			}
		})
	}
}

func testSigningKeyMaterial(t *testing.T) (privateDER, privatePEM, publicDER, publicPEM []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privateDER, privatePEM, publicDER, publicPEM
}
