package cryptobrokerclientgo

import (
	"context"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
)

func TestVerifyData(t *testing.T) {
	client := &mockedGRPCClient{}
	lib := &Library{client: client}
	key := KeySource{RawKey: []byte("public key")}
	client.On("VerifyData", mock.Anything, mock.MatchedBy(func(request *protobuf.VerifyDataRequest) bool {
		return request.GetProfile() == "Default" &&
			string(request.GetInput()) == "document" &&
			string(request.GetSignature()) == "signature" &&
			string(request.GetKeySource().GetSingle().GetRawKey()) == "public key"
	})).Return(&protobuf.VerifyDataResponse{Valid: true}, nil).Once()

	response, err := lib.VerifyData(context.Background(), VerifyDataPayload{
		Profile:   "Default",
		KeySource: SignKeySource{Single: &key},
		Input:     []byte("document"),
		Signature: []byte("signature"),
	})
	if err != nil {
		t.Fatalf("VerifyData() error: %v", err)
	}
	if !response.GetValid() {
		t.Fatal("VerifyData() valid = false, want true")
	}
	client.AssertExpectations(t)
}
