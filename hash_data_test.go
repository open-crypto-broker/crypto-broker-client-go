package cryptobrokerclientgo

import (
	"context"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	protobuf "github.com/open-crypto-broker/crypto-broker-client-go/internal/gen/cryptobroker/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestLibrary_HashDataRejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name   string
		change func(*HashDataPayload)
		field  string
	}{
		{"zero payload (nil is not representable)", func(p *HashDataPayload) { *p = HashDataPayload{} }, "profile"},
		{"nil input", func(p *HashDataPayload) { p.Input = nil }, "input"},
		{"empty profile", func(p *HashDataPayload) { p.Profile = "" }, "profile"},
		{"long profile", func(p *HashDataPayload) {
			p.Profile = strings.Repeat("A", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_PROFILE_MAX_LEN)+1)
		}, "profile"},
		{"large input", func(p *HashDataPayload) {
			p.Input = make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_HASH_DATA_INPUT_MAX_LEN)+1)
		}, "input"},
		{"invalid output format", func(p *HashDataPayload) { p.OutputFormat = OutputFormatHash(20) }, "output format"},
		{"long trace ID", func(p *HashDataPayload) {
			p.Metadata = &Metadata{TraceContext: &TraceContext{TraceId: strings.Repeat("0", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_ID_MAX_LEN)+1)}}
		}, "metadata.traceContext.traceId"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			// An unexpected call returns a response so the explicit no-call assertion also runs.
			client.On("HashData", mock.Anything, mock.Anything).Return(&protobuf.HashDataResponse{}, nil)
			payload := HashDataPayload{Profile: "Default", Input: []byte("Hello world"), OutputFormat: OutputFormatHex}
			tt.change(&payload)
			response, err := (&Library{client: client}).HashData(context.Background(), payload)
			client.AssertNotCalled(t, "HashData", mock.Anything, mock.Anything)
			require.ErrorContains(t, err, tt.field)
			require.Nil(t, response)
		})
	}
}

func TestLibrary_HashDataCreatesMetadata(t *testing.T) {
	for _, input := range [][]byte{[]byte("Hello world"), {}} {
		client := &mockedGRPCClient{}
		client.On("HashData", mock.Anything, mock.MatchedBy(func(req *protobuf.HashDataRequest) bool {
			id, err := uuid.Parse(req.GetMetadata().GetId())
			return err == nil && id.Version() == 4 && id.Variant() == uuid.RFC4122 &&
				req.GetMetadata().GetTraceContext() == nil
		})).Return(&protobuf.HashDataResponse{}, nil).Once()
		_, err := (&Library{client: client}).HashData(context.Background(), HashDataPayload{
			Profile: "Default", Input: input, Metadata: nil, OutputFormat: OutputFormatHex,
		})
		require.NoError(t, err)
		client.AssertExpectations(t)
	}
}

func TestLibrary_HashData(t *testing.T) {
	mockedClient := &mockedGRPCClient{}

	const referenceDigest = "e2e1c9e522efb2495a178434c8bb8f11000ca23f1fd679058b7d7e141f0cf3433f94fc427ec0b9bebb12f327a3240021053db6091196576d5e6d9bd8fac71c0c"
	digest := sha3.Sum512([]byte("Hello world"))
	require.Equal(t, referenceDigest, hex.EncodeToString(digest[:]))
	rawDigest, err := hex.DecodeString(referenceDigest)
	require.NoError(t, err)

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoServiceClient
		conn   *grpc.ClientConn
	}
	type args struct {
		ctx     context.Context
		payload HashDataPayload
	}
	tests := []struct {
		name     string
		fields   fields
		mockFunc mockFunc
		args     args
		want     *protobuf.HashDataResponse
		wantErr  bool
	}{
		{
			name: "HashData() succeeds when client returns response without error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.HashDataResponse{
					HashValue:   &protobuf.HashDataResponse_HashValueHex{HashValueHex: referenceDigest},
					Descriptor_: &protobuf.CryptoDescriptor{Algorithm: "sha3-512"},
				}
				mockedClient.On("HashData", mock.Anything, mock.MatchedBy(func(req *protobuf.HashDataRequest) bool {
					return req.GetProfile() == "Default" && string(req.GetInput()) == "Hello world" && req.GetMetadata().GetId() == "123" && req.GetOutputFormat() == protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_HEX
				})).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					OutputFormat: OutputFormatHex,
					Profile:      "Default",
					Input:        []byte("Hello world"),
					Metadata: &Metadata{
						Id: "123",
					},
				},
			},
			want: &protobuf.HashDataResponse{
				HashValue:   &protobuf.HashDataResponse_HashValueHex{HashValueHex: referenceDigest},
				Descriptor_: &protobuf.CryptoDescriptor{Algorithm: "sha3-512"},
			},
			wantErr: false,
		},
		{
			name: "HashData() succeeds when client returns raw digest bytes response",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.HashDataResponse{
					HashValue:   &protobuf.HashDataResponse_HashValueRaw{HashValueRaw: rawDigest},
					Descriptor_: &protobuf.CryptoDescriptor{Algorithm: "sha3-512"},
				}
				mockedClient.On("HashData", mock.Anything, mock.MatchedBy(func(req *protobuf.HashDataRequest) bool {
					return req.GetProfile() == "Default" && string(req.GetInput()) == "Hello world" && req.GetMetadata().GetId() == "123" && req.GetOutputFormat() == protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW
				})).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					Profile:      "Default",
					Input:        []byte("Hello world"),
					OutputFormat: OutputFormatRaw,
					Metadata: &Metadata{
						Id: "123",
					},
				},
			},
			want: &protobuf.HashDataResponse{
				HashValue:   &protobuf.HashDataResponse_HashValueRaw{HashValueRaw: rawDigest},
				Descriptor_: &protobuf.CryptoDescriptor{Algorithm: "sha3-512"},
			},
			wantErr: false,
		},
		{
			name: "HashData() fails when client returns non-nil error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("HashData", mock.Anything, mock.Anything).
					Return(&protobuf.HashDataResponse{}, errors.New("some error")).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					OutputFormat: OutputFormatHex,
					Profile:      "Default",
					Input:        []byte("Hello world"),
					Metadata: &Metadata{
						Id: "123",
					},
				},
			},
			want:    &protobuf.HashDataResponse{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib := &Library{
				client: tt.fields.client,
				conn:   tt.fields.conn,
			}

			tt.mockFunc()
			t.Cleanup(func() { mockedClient.AssertExpectations(t) })

			got, err := lib.HashData(tt.args.ctx, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("Library.HashData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Library.HashData() = %v, want %v", got, tt.want)
			}
		})
	}
}
