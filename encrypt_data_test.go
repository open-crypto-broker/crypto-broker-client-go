package cryptobrokerclientgo

import (
	"context"
	"errors"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
)

func TestLibrary_EncryptData(t *testing.T) {
	tests := []struct {
		name    string
		payload EncryptDataPayload
		setup   func(*mockedGRPCClient) *protobuf.EncryptDataResponse
		wantErr error
	}{
		{
			name: "maps caller-managed encryption payload",
			payload: EncryptDataPayload{
				Profile:   "FIPS-140-3-256bit",
				KeySource: KeySource{RawKey: []byte("0123456789abcdef0123456789abcdef")},
				Plaintext: []byte("plaintext"),
				Nonce:     []byte("123456789012"),
				AAD:       []byte("aad"),
				Metadata: &Metadata{
					Id: "request-id",
					TraceContext: &TraceContext{
						TraceId:       "trace-id",
						SpanId:        "span-id",
						TraceFlags:    "01",
						TraceState:    "state",
						CorrelationId: "correlation-id",
					},
				},
			},
			setup: func(client *mockedGRPCClient) *protobuf.EncryptDataResponse {
				response := &protobuf.EncryptDataResponse{Ciphertext: []byte("ciphertext")}
				client.On("EncryptData", mock.Anything, mock.MatchedBy(func(request *protobuf.EncryptDataRequest) bool {
					if request == nil || request.GetProfile() != "FIPS-140-3-256bit" ||
						string(request.GetKeySource().GetRawKey()) != "0123456789abcdef0123456789abcdef" ||
						string(request.GetPlaintext()) != "plaintext" ||
						string(request.GetEncryptMetadata().GetNonce()) != "123456789012" ||
						string(request.GetEncryptMetadata().GetAad()) != "aad" {
						return false
					}
					traceContext := request.GetMetadata().GetTraceContext()
					return request.GetMetadata().GetId() == "request-id" &&
						traceContext.GetTraceId() == "trace-id" &&
						traceContext.GetSpanId() == "span-id" &&
						traceContext.GetTraceFlags() == "01" &&
						traceContext.GetTraceState() == "state" &&
						traceContext.GetCorrelationId() == "correlation-id"
				})).Return(response, nil).Once()
				return response
			},
		},
		{
			name: "creates metadata when omitted",
			payload: EncryptDataPayload{
				KeySource: KeySource{RawKey: []byte("0123456789abcdef0123456789abcdef")},
			},
			setup: func(client *mockedGRPCClient) *protobuf.EncryptDataResponse {
				response := &protobuf.EncryptDataResponse{}
				client.On("EncryptData", mock.Anything, mock.MatchedBy(func(request *protobuf.EncryptDataRequest) bool {
					return request != nil && request.GetMetadata() != nil && request.GetMetadata().GetId() != "" &&
						request.GetMetadata().GetTraceContext() == nil
				})).Return(response, nil).Once()
				return response
			},
		},
		{
			name: "propagates RPC error",
			payload: EncryptDataPayload{
				KeySource: KeySource{RawKey: []byte("0123456789abcdef0123456789abcdef")},
			},
			setup: func(client *mockedGRPCClient) *protobuf.EncryptDataResponse {
				client.On("EncryptData", mock.Anything, mock.Anything).Return(&protobuf.EncryptDataResponse{}, errors.New("RPC error")).Once()
				return nil
			},
			wantErr: errors.New("RPC error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			want := tt.setup(client)

			got, err := (&Library{client: client}).EncryptData(context.Background(), tt.payload)
			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("EncryptData() error = %v, want error %v", err, tt.wantErr)
			}
			if err == nil && got != want {
				t.Fatalf("EncryptData() response = %p, want %p", got, want)
			}
			client.AssertExpectations(t)
		})
	}
}

func TestLibrary_EncryptDataRejectsInvalidKeySource(t *testing.T) {
	tests := []KeySource{
		{},
		{KeyID: "key-id", RawKey: []byte("raw-key")},
	}

	for _, keySource := range tests {
		_, err := (&Library{client: &mockedGRPCClient{}}).EncryptData(context.Background(), EncryptDataPayload{KeySource: keySource})
		if !errors.Is(err, ErrInvalidKeySource) {
			t.Fatalf("EncryptData() error = %v, want ErrInvalidKeySource", err)
		}
	}
}
