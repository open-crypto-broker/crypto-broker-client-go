package cryptobrokerclientgo

import (
	"context"
	"errors"
	"testing"

	protobuf "github.com/open-crypto-broker/crypto-broker-client-go/internal/gen/cryptobroker/v1"
	"github.com/stretchr/testify/mock"
)

func TestSignData(t *testing.T) {
	client := &mockedGRPCClient{}
	lib := &Library{client: client}
	privateDER, _ := testSigningKeyMaterial(t)
	key := KeySource{RawKey: privateDER}
	client.On("SignData", mock.Anything, mock.MatchedBy(func(request *protobuf.SignDataRequest) bool {
		return request.GetProfile() == "Default" &&
			string(request.GetInput()) == "document" &&
			string(request.GetKeySource().GetSingle().GetRawKey()) == string(privateDER) &&
			request.GetSignatureFormat() == protobuf.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED
	})).Return(&protobuf.SignDataResponse{Signature: []byte("signature")}, nil).Once()

	response, err := lib.SignData(context.Background(), SignDataPayload{
		Profile:   "Default",
		KeySource: SignKeySource{Single: &key},
		Input:     []byte("document"),
	})
	if err != nil {
		t.Fatalf("SignData() error: %v", err)
	}
	if string(response.GetSignature()) != "signature" {
		t.Fatalf("signature = %q, want signature", response.GetSignature())
	}
	client.AssertExpectations(t)
}

func TestSignKeySourceToProto(t *testing.T) {
	_, err := (SignKeySource{}).toProtoWithRawKeyEncoder(privateKeyDER)
	if !errors.Is(err, ErrInvalidSignKeySource) {
		t.Fatalf("empty SignKeySource error = %v, want %v", err, ErrInvalidSignKeySource)
	}

	key := KeySource{RawKey: []byte("key")}
	_, err = (SignKeySource{Single: &key, ComponentKeys: []KeySource{key}}).toProtoWithRawKeyEncoder(privateKeyDER)
	if !errors.Is(err, ErrInvalidSignKeySource) {
		t.Fatalf("mixed SignKeySource error = %v, want %v", err, ErrInvalidSignKeySource)
	}
}
