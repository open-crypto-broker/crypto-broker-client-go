package cryptobrokerclientgo

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

func TestLibrary_HashData(t *testing.T) {
	mockedClient := &mockedGRPCClient{}

	rawDigest := []byte{
		0x36, 0x91, 0x83, 0xd3, 0x78, 0x67, 0x73, 0xce, 0xf4, 0xe5, 0x6c, 0x7b, 0x84, 0x9e, 0x7e, 0xf5,
		0xf7, 0x42, 0x86, 0x75, 0x10, 0xb6, 0x76, 0xd6, 0xb3, 0x8f, 0x8e, 0x38, 0xa2, 0x22, 0xd8, 0xa2,
	}

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoGrpcClient
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
		want     *protobuf.HashResponse
		wantErr  bool
	}{
		{
			name: "HashData() succeeds when client returns response without error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.HashResponse{
					HashValue:     &protobuf.HashResponse_HashValueHex{HashValueHex: "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a"},
					HashAlgorithm: "sha3-512",
				}
				mockedClient.On("Hash", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					Profile: "Default",
					Input:   []byte("Hello world"),
					Metadata: &Metadata{
						Id: "123",
					},
				},
			},
			want: &protobuf.HashResponse{
				HashValue:     &protobuf.HashResponse_HashValueHex{HashValueHex: "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a"},
				HashAlgorithm: "sha3-512",
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
				resp := &protobuf.HashResponse{
					HashValue:     &protobuf.HashResponse_HashValueRaw{HashValueRaw: rawDigest},
					HashAlgorithm: "sha3-256",
				}
				mockedClient.On("Hash", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					Profile:          "Default",
					Input:            []byte("Hello world"),
					OutputFormat: OutputFormatRaw,
					Metadata: &Metadata{
						Id: "123",
					},
				},
			},
			want: &protobuf.HashResponse{
				HashValue:     &protobuf.HashResponse_HashValueRaw{HashValueRaw: rawDigest},
				HashAlgorithm: "sha3-256",
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
				mockedClient.On("Hash", mock.Anything, mock.Anything).
					Return(&protobuf.HashResponse{}, errors.New("some error")).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					Profile: "Default",
					Input:   []byte("Hello world"),
					Metadata: &Metadata{
						Id: "123",
					},
				},
			},
			want:    &protobuf.HashResponse{},
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
