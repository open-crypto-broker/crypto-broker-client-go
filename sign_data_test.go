package cryptobrokerclientgo

import (
	"context"
	"errors"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
)

func TestSignData(t *testing.T) {
	client := &mockedGRPCClient{}
	lib := &Library{client: client}
	key := KeySource{RawKey: []byte("private key")}
	client.On("SignData", mock.Anything, mock.MatchedBy(func(request *protobuf.SignDataRequest) bool {
		return request.GetProfile() == "Default" &&
			string(request.GetInput()) == "document" &&
			string(request.GetKeySource().GetSingle().GetRawKey()) == "private key" &&
			request.SignatureFormat == nil
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
	_, err := (SignKeySource{}).toProto()
	if !errors.Is(err, ErrInvalidSignKeySource) {
		t.Fatalf("empty SignKeySource error = %v, want %v", err, ErrInvalidSignKeySource)
	}

	key := KeySource{RawKey: []byte("key")}
	_, err = (SignKeySource{Single: &key, ComponentKeys: []KeySource{key}}).toProto()
	if !errors.Is(err, ErrInvalidSignKeySource) {
		t.Fatalf("mixed SignKeySource error = %v, want %v", err, ErrInvalidSignKeySource)
	}
}
