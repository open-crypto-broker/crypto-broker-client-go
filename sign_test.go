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

func TestLibrary_SignCertificate(t *testing.T) {
	mockedClient := &mockedCryptoBrokerClient{}

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoBrokerClient
		conn   *grpc.ClientConn
	}
	type args struct {
		ctx     context.Context
		payload SignCertificatePayload
	}
	tests := []struct {
		name     string
		fields   fields
		mockFunc mockFunc
		args     args
		want     *protobuf.SignResponse
		wantErr  bool
	}{
		{
			name: "SignCertificate() succeeds when client returns response without error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.SignResponse{SignedCertificate: "PEM signed cert"}
				mockedClient.On("Sign", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{},
			},
			want:    &protobuf.SignResponse{SignedCertificate: "PEM signed cert"},
			wantErr: false,
		},
		{
			name: "SignCertificate() fails when client returns non-nil error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("Sign", mock.Anything, mock.Anything).
					Return(&protobuf.SignResponse{}, errors.New("some error")).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{},
			},
			want:    &protobuf.SignResponse{},
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

			got, err := lib.SignCertificate(tt.args.ctx, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("Library.SignCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Library.SignCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
