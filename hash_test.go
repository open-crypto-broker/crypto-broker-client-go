package cryptobrokerclientgo

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.tools.sap/apeirora-crypto-agility/crypto-broker-client-go/internal/protobuf"
	"google.golang.org/grpc"
)

type mockedCryptoBrokerClient struct {
	mock.Mock
}

func (m *mockedCryptoBrokerClient) Hash(ctx context.Context, in *protobuf.HashRequest, opts ...grpc.CallOption) (*protobuf.HashResponse, error) {
	args := m.Called(ctx, in)

	return args.Get(0).(*protobuf.HashResponse), args.Error(1)
}

func (m *mockedCryptoBrokerClient) Sign(ctx context.Context, in *protobuf.SignRequest, opts ...grpc.CallOption) (*protobuf.SignResponse, error) {
	args := m.Called(ctx, in)

	return args.Get(0).(*protobuf.SignResponse), args.Error(1)
}

func TestLibrary_HashData(t *testing.T) {
	mockedClient := &mockedCryptoBrokerClient{}

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoBrokerClient
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
				resp := &protobuf.HashResponse{HashValue: "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a", HashAlgorithm: "sha3-512"}
				mockedClient.On("Hash", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: HashDataPayload{
					Profile: "Default",
					Input:   []byte("Hello world"),
					Metadata: &Metadata{
						Id:        "123",
						CreatedAt: "Today",
					},
				},
			},
			want:    &protobuf.HashResponse{HashValue: "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a", HashAlgorithm: "sha3-512"},
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
						Id:        "123",
						CreatedAt: "Today",
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
