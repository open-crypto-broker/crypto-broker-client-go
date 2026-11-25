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

func TestSigningKeyPEMRejectedBeforeRPC(t *testing.T) {
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{"private", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})},
		{"public with leading whitespace", append([]byte(" \n\t"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})...)},
		{"certificate", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})},
		{"malformed PEM", []byte("-----BEGIN broken")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			lib := &Library{client: client}
			source := SignKeySource{Single: &KeySource{RawKey: test.key}}
			if _, err := lib.SignData(context.Background(), SignDataPayload{KeySource: source}); err == nil {
				t.Error("SignData accepted PEM")
			}
			if _, err := lib.SignCertificate(context.Background(), SignCertificatePayload{
				KeySource: source, CACert: []byte("CA certificate"), OutputFormat: OutputFormatDer,
			}); err == nil {
				t.Error("SignCertificate accepted PEM")
			}
			if _, err := lib.VerifyData(context.Background(), VerifyDataPayload{KeySource: source}); err == nil {
				t.Error("VerifyData accepted PEM")
			}
			client.AssertNotCalled(t, "SignData")
			client.AssertNotCalled(t, "SignCertificate")
			client.AssertNotCalled(t, "VerifyData")
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
