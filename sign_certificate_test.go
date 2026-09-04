package cryptobrokerclientgo

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

func TestLibrary_SignCertificate(t *testing.T) {
	mockedClient := &mockedGRPCClient{}
	zeroTime := time.Time{}
	currentTime := time.Now()

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoGrpcClient
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
		want     *protobuf.SignCertificateResponse
		wantErr  bool
	}{
		{
			name: "SignCertificate() succeeds when client returns response without error and PEM encoding is used",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.SignCertificateResponse{
					SignedCertificate: &protobuf.SignCertificateResponse_Pem{Pem: "-----BEGIN CERTIFICATE-----\nMIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQw\ngYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0\nLU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAo\nBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5\nMTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAx\nMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuz\nGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjf\npxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMC\nBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW\ngBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwR\nmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0W\ns4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8=\n-----END CERTIFICATE-----\n"},
				}
				mockedClient.On("SignCertificate", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{OutputFormat: OutputFormatPem},
			},
			want: &protobuf.SignCertificateResponse{
				SignedCertificate: &protobuf.SignCertificateResponse_Pem{Pem: "-----BEGIN CERTIFICATE-----\nMIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQw\ngYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0\nLU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAo\nBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5\nMTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAx\nMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuz\nGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjf\npxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMC\nBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW\ngBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwR\nmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0W\ns4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8=\n-----END CERTIFICATE-----\n"},
			},
			wantErr: false,
		},
		{
			name: "SignCertificate() succeeds when client returns response without error and DER encoding is used",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.SignCertificateResponse{
					SignedCertificate: &protobuf.SignCertificateResponse_Der{Der: []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x50, 0x4b, 0x03, 0x04}},
				}
				mockedClient.On("SignCertificate", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{OutputFormat: OutputFormatDer},
			},
			want: &protobuf.SignCertificateResponse{
				SignedCertificate: &protobuf.SignCertificateResponse_Der{Der: []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x50, 0x4b, 0x03, 0x04}},
			},
			wantErr: false,
		},
		{
			name: "SignCertificate() fails when client returns non-nil error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("SignCertificate", mock.Anything, mock.Anything).
					Return(&protobuf.SignCertificateResponse{}, errors.New("some error")).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "SignCertificate() fails when client asks for unsupported output format",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{OutputFormat: OutputFormatSign(20)},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "SignCertificate() fails when user provides invalid NotBefore timestamp",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {

			},
			args: args{
				ctx: context.TODO(),
				payload: SignCertificatePayload{
					ValidNotBefore: &zeroTime,
					ValidNotAfter:  &currentTime,
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "SignCertificate() fails when user provides invalid NotAfter timestamp",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {

			},
			args: args{
				ctx: context.TODO(),
				payload: SignCertificatePayload{
					ValidNotBefore: &currentTime,
					ValidNotAfter:  &zeroTime,
				},
			},
			want:    nil,
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
