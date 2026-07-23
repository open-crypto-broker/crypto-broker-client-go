package cryptobrokerclientgo

import (
	"context"
	"errors"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
)

func TestLibrary_DecryptData(t *testing.T) {
	tests := []struct {
		name    string
		payload DecryptDataPayload
		setup   func(*mockedGRPCClient) *protobuf.DecryptDataResponse
		wantErr error
	}{
		{
			name: "maps managed-key decryption payload",
			payload: DecryptDataPayload{
				Profile:    "FIPS-140-3-256bit",
				KeySource:  KeySource{KeyID: "managed-key"},
				Ciphertext: []byte("ciphertext"),
				Nonce:      []byte("123456789012"),
				AAD:        []byte("aad"),
				Tag:        []byte("1234567890123456"),
				Metadata:   &Metadata{Id: "request-id"},
			},
			setup: func(client *mockedGRPCClient) *protobuf.DecryptDataResponse {
				response := &protobuf.DecryptDataResponse{Plaintext: []byte("plaintext")}
				client.On("DecryptData", mock.Anything, mock.MatchedBy(func(request *protobuf.DecryptDataRequest) bool {
					return request != nil && request.GetProfile() == "FIPS-140-3-256bit" &&
						request.GetKeySource().GetKeyId() == "managed-key" &&
						string(request.GetCiphertext()) == "ciphertext" &&
						string(request.GetDecryptMetadata().GetNonce()) == "123456789012" &&
						string(request.GetDecryptMetadata().GetAad()) == "aad" &&
						string(request.GetDecryptMetadata().GetTag()) == "1234567890123456" &&
						request.GetMetadata().GetId() == "request-id"
				})).Return(response, nil).Once()
				return response
			},
		},
		{
			name: "creates metadata when omitted",
			payload: DecryptDataPayload{
				KeySource: KeySource{RawKey: []byte("0123456789abcdef0123456789abcdef")},
			},
			setup: func(client *mockedGRPCClient) *protobuf.DecryptDataResponse {
				response := &protobuf.DecryptDataResponse{}
				client.On("DecryptData", mock.Anything, mock.MatchedBy(func(request *protobuf.DecryptDataRequest) bool {
					return request != nil && request.GetMetadata() != nil && request.GetMetadata().GetId() != "" &&
						request.GetMetadata().GetTraceContext() == nil
				})).Return(response, nil).Once()
				return response
			},
		},
		{
			name: "propagates RPC error",
			payload: DecryptDataPayload{
				KeySource: KeySource{RawKey: []byte("0123456789abcdef0123456789abcdef")},
			},
			setup: func(client *mockedGRPCClient) *protobuf.DecryptDataResponse {
				client.On("DecryptData", mock.Anything, mock.Anything).Return(&protobuf.DecryptDataResponse{}, errors.New("RPC error")).Once()
				return nil
			},
			wantErr: errors.New("RPC error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			want := tt.setup(client)

			got, err := (&Library{client: client}).DecryptData(context.Background(), tt.payload)
			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("DecryptData() error = %v, want error %v", err, tt.wantErr)
			}
			if err == nil && got != want {
				t.Fatalf("DecryptData() response = %p, want %p", got, want)
			}
			client.AssertExpectations(t)
		})
	}
}

func TestLibrary_DecryptDataRejectsInvalidKeySource(t *testing.T) {
	tests := []KeySource{
		{},
		{KeyID: "key-id", RawKey: []byte("raw-key")},
	}

	for _, keySource := range tests {
		_, err := (&Library{client: &mockedGRPCClient{}}).DecryptData(context.Background(), DecryptDataPayload{KeySource: keySource})
		if !errors.Is(err, ErrInvalidKeySource) {
			t.Fatalf("DecryptData() error = %v, want ErrInvalidKeySource", err)
		}
	}
}
