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
	"errors"
	"math/big"
	"testing"
	"time"

	protobuf "github.com/open-crypto-broker/crypto-broker-client-go/internal/gen/cryptobroker/v1"
	"github.com/stretchr/testify/mock"
)

func TestInvalidPrivateKeyPEMRejectedBeforeRPC(t *testing.T) {
	valid := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{"public with leading whitespace", append([]byte(" \n\t"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})...)},
		{"certificate", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})},
		{"PKCS1 private", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}})},
		{"SEC1 private", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})},
		{"encrypted PKCS8", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})},
		{"custom ML-DSA", pem.EncodeToMemory(&pem.Block{Type: "ML-DSA PRIVATE KEY", Bytes: []byte{1}})},
		{"headers", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})},
		{"multiple blocks", append(bytes.Clone(valid), valid...)},
		{"trailing data", append(bytes.Clone(valid), []byte("trailing")...)},
		{"malformed PEM", []byte("-----BEGIN broken")},
		{"malformed followed by valid", append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n"), valid...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			lib := &Library{client: client}
			source := SignKeySource{Single: &KeySource{RawKey: test.key}}
			if _, err := lib.SignData(context.Background(), SignDataPayload{KeySource: source}); err == nil {
				t.Error("SignData accepted invalid PEM")
			}
			if _, err := lib.SignCertificate(context.Background(), SignCertificatePayload{
				KeySource: source, CACert: []byte("CA certificate"), OutputFormat: OutputFormatDer,
			}); err == nil {
				t.Error("SignCertificate accepted invalid PEM")
			}
			client.AssertNotCalled(t, "SignData")
			client.AssertNotCalled(t, "SignCertificate")
		})
	}
}

func TestPrivateKeyPEMDecodedBeforeRPC(t *testing.T) {
	privateDER, _ := testSigningKeyMaterial(t)
	for _, test := range []struct {
		name string
		der  []byte
	}{
		{"PKCS8", privateDER},
		{"unvalidated DER", []byte{0x30, 0x01, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			lib := &Library{client: client}
			encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: test.der})
			encoded = append(append([]byte(" \n\t"), encoded...), []byte(" \r\n")...)
			source := SignKeySource{Single: &KeySource{RawKey: encoded}}
			client.On("SignData", mock.Anything, mock.MatchedBy(func(req *protobuf.SignDataRequest) bool {
				return bytes.Equal(req.GetKeySource().GetSingle().GetRawKey(), test.der)
			})).Return(&protobuf.SignDataResponse{}, nil).Once()
			client.On("SignCertificate", mock.Anything, mock.MatchedBy(func(req *protobuf.SignCertificateRequest) bool {
				return bytes.Equal(req.GetKeySource().GetSingle().GetRawKey(), test.der)
			})).Return(&protobuf.SignCertificateResponse{}, nil).Once()
			if _, err := lib.SignData(context.Background(), SignDataPayload{KeySource: source}); err != nil {
				t.Errorf("SignData error = %v", err)
			}
			if _, err := lib.SignCertificate(context.Background(), SignCertificatePayload{
				KeySource: source, CACert: []byte("CA certificate"), OutputFormat: OutputFormatDer,
			}); err != nil {
				t.Errorf("SignCertificate error = %v", err)
			}
			client.AssertExpectations(t)
		})
	}
}

func TestPrivateKeyPEMDecodedInComponentKeys(t *testing.T) {
	der := []byte{0x30, 0x01, 0xff}
	source := SignKeySource{ComponentKeys: []KeySource{
		{RawKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
		{KeyID: "managed-key"},
	}}
	client := &mockedGRPCClient{}
	client.On("SignData", mock.Anything, mock.MatchedBy(func(req *protobuf.SignDataRequest) bool {
		keys := req.GetKeySource().GetComponentKeys().GetKeys()
		return len(keys) == 2 && bytes.Equal(keys[0].GetRawKey(), der) && keys[1].GetKeyId() == "managed-key"
	})).Return(&protobuf.SignDataResponse{}, nil).Once()
	if _, err := (&Library{client: client}).SignData(context.Background(), SignDataPayload{KeySource: source}); err != nil {
		t.Fatalf("SignData error = %v", err)
	}
	client.AssertExpectations(t)
}

func TestVerifyDataRejectsPrivateKeyPEM(t *testing.T) {
	client := &mockedGRPCClient{}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	if _, err := (&Library{client: client}).VerifyData(context.Background(), VerifyDataPayload{
		KeySource: SignKeySource{Single: &KeySource{RawKey: key}},
	}); err == nil {
		t.Fatal("VerifyData accepted PEM")
	}
	client.AssertNotCalled(t, "VerifyData")
}

func TestVerifyDataDecodesPublicKeyPEMBeforeRPC(t *testing.T) {
	_, publicDER := testSigningKeyMaterial(t)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	publicPEM = append(append([]byte(" \n\t"), publicPEM...), []byte(" \r\n")...)

	for _, test := range []struct {
		name      string
		keySource SignKeySource
		matches   func(*protobuf.VerifyDataRequest) bool
	}{
		{
			name:      "single PEM key",
			keySource: SignKeySource{Single: &KeySource{RawKey: publicPEM}},
			matches: func(req *protobuf.VerifyDataRequest) bool {
				return bytes.Equal(req.GetKeySource().GetSingle().GetRawKey(), publicDER)
			},
		},
		{
			name: "component PEM and DER keys",
			keySource: SignKeySource{ComponentKeys: []KeySource{
				{RawKey: publicPEM},
				{RawKey: publicDER},
			}},
			matches: func(req *protobuf.VerifyDataRequest) bool {
				keys := req.GetKeySource().GetComponentKeys().GetKeys()
				return len(keys) == 2 && bytes.Equal(keys[0].GetRawKey(), publicDER) && bytes.Equal(keys[1].GetRawKey(), publicDER)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			client.On("VerifyData", mock.Anything, mock.MatchedBy(test.matches)).Return(&protobuf.VerifyDataResponse{}, nil).Once()
			if _, err := (&Library{client: client}).VerifyData(context.Background(), VerifyDataPayload{KeySource: test.keySource}); err != nil {
				t.Fatalf("VerifyData error = %v", err)
			}
			client.AssertExpectations(t)
		})
	}
}

func TestSigningKeyBytesPassedUnchanged(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	serverErr := errors.New("server rejected key")
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{"unrecognized DER", []byte{0x30, 0x01, 0xff}},
		{"PKCS1 private", x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"SEC1 private", sec1DER},
		{"PKCS1 public", x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)},
		{"certificate", certificate},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			lib := &Library{client: client}
			source := SignKeySource{Single: &KeySource{RawKey: test.key}}
			client.On("SignData", mock.Anything, mock.MatchedBy(func(req *protobuf.SignDataRequest) bool {
				return bytes.Equal(req.GetKeySource().GetSingle().GetRawKey(), test.key)
			})).Return(&protobuf.SignDataResponse{}, serverErr).Once()
			client.On("SignCertificate", mock.Anything, mock.MatchedBy(func(req *protobuf.SignCertificateRequest) bool {
				return bytes.Equal(req.GetKeySource().GetSingle().GetRawKey(), test.key)
			})).Return(&protobuf.SignCertificateResponse{}, serverErr).Once()
			client.On("VerifyData", mock.Anything, mock.MatchedBy(func(req *protobuf.VerifyDataRequest) bool {
				return bytes.Equal(req.GetKeySource().GetSingle().GetRawKey(), test.key)
			})).Return(&protobuf.VerifyDataResponse{}, serverErr).Once()

			_, err := lib.SignData(context.Background(), SignDataPayload{KeySource: source})
			if !errors.Is(err, serverErr) {
				t.Errorf("SignData error = %v, want server error", err)
			}
			_, err = lib.SignCertificate(context.Background(), SignCertificatePayload{
				KeySource: source, CACert: []byte("CA certificate"), OutputFormat: OutputFormatDer,
			})
			if !errors.Is(err, serverErr) {
				t.Errorf("SignCertificate error = %v, want server error", err)
			}
			_, err = lib.VerifyData(context.Background(), VerifyDataPayload{KeySource: source})
			if !errors.Is(err, serverErr) {
				t.Errorf("VerifyData error = %v, want server error", err)
			}
			client.AssertExpectations(t)
		})
	}
}

func TestComponentSigningKeyBytesPassedUnchanged(t *testing.T) {
	client := &mockedGRPCClient{}
	lib := &Library{client: client}
	raw := []byte{0x30, 0x01, 0xff}
	source := SignKeySource{ComponentKeys: []KeySource{
		{RawKey: raw},
		{KeyID: "managed-key"},
	}}
	matches := func(keys *protobuf.ComponentKeys) bool {
		return len(keys.GetKeys()) == 2 &&
			bytes.Equal(keys.GetKeys()[0].GetRawKey(), raw) &&
			keys.GetKeys()[1].GetKeyId() == "managed-key"
	}
	client.On("SignData", mock.Anything, mock.MatchedBy(func(req *protobuf.SignDataRequest) bool {
		return matches(req.GetKeySource().GetComponentKeys())
	})).Return(&protobuf.SignDataResponse{}, nil).Once()
	client.On("VerifyData", mock.Anything, mock.MatchedBy(func(req *protobuf.VerifyDataRequest) bool {
		return matches(req.GetKeySource().GetComponentKeys())
	})).Return(&protobuf.VerifyDataResponse{}, nil).Once()

	if _, err := lib.SignData(context.Background(), SignDataPayload{KeySource: source}); err != nil {
		t.Errorf("SignData error = %v", err)
	}
	if _, err := lib.VerifyData(context.Background(), VerifyDataPayload{KeySource: source}); err != nil {
		t.Errorf("VerifyData error = %v", err)
	}
	client.AssertExpectations(t)
}

func TestComponentSigningKeysRejectPEM(t *testing.T) {
	client := &mockedGRPCClient{}
	lib := &Library{client: client}
	source := SignKeySource{ComponentKeys: []KeySource{
		{RawKey: []byte{0x30, 0x00}},
		{RawKey: []byte("-----BEGIN PUBLIC KEY-----")},
	}}
	if _, err := lib.SignData(context.Background(), SignDataPayload{KeySource: source}); err == nil {
		t.Error("SignData accepted a PEM component key")
	}
	if _, err := lib.VerifyData(context.Background(), VerifyDataPayload{KeySource: source}); err == nil {
		t.Error("VerifyData accepted a PEM component key")
	}
	client.AssertNotCalled(t, "SignData")
	client.AssertNotCalled(t, "VerifyData")
}

func testSigningKeyMaterial(t *testing.T) (privateDER, publicDER []byte) {
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
	return privateDER, publicDER
}
