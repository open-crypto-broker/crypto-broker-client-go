package cryptobrokerclientgo

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	protobuf "github.com/open-crypto-broker/crypto-broker-client-go/internal/gen/cryptobroker/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestLibrary_SignCertificateRejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name   string
		change func(*SignCertificatePayload)
		field  string
	}{
		{"zero payload (nil is not representable)", func(p *SignCertificatePayload) { *p = SignCertificatePayload{} }, "profile"},
		{"empty profile", func(p *SignCertificatePayload) { p.Profile = "" }, "profile"},
		{"empty CSR", func(p *SignCertificatePayload) { p.CSR = []byte{} }, "csr"},
		{"missing CA key", func(p *SignCertificatePayload) { p.CAPrivateKey = nil }, "caPrivateKey"},
		{"missing CA certificate", func(p *SignCertificatePayload) { p.CACert = nil }, "caCert"},
		{"long profile", func(p *SignCertificatePayload) {
			p.Profile = strings.Repeat("A", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_PROFILE_MAX_LEN)+1)
		}, "profile"},
		{"large CSR", func(p *SignCertificatePayload) {
			p.CSR = make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CSR_MAX_LEN)+1)
		}, "csr"},
		{"large CA key", func(p *SignCertificatePayload) {
			p.CAPrivateKey = make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_PRIVATE_KEY_MAX_LEN)+1)
		}, "caPrivateKey"},
		{"large CA certificate", func(p *SignCertificatePayload) {
			p.CACert = make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_CERT_MAX_LEN)+1)
		}, "caCert"},
		{"long subject", func(p *SignCertificatePayload) {
			s := strings.Repeat("A", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_SUBJECT_MAX_LEN)+1)
			p.Subject = &s
		}, "subject"},
		{"too many CRL points", func(p *SignCertificatePayload) {
			p.CrlDistributionPoints = make([]string, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINTS_MAX)+1)
		}, "crlDistributionPoints"},
		{"long CRL point", func(p *SignCertificatePayload) {
			p.CrlDistributionPoints = []string{strings.Repeat("A", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINT_MAX_LEN)+1)}
		}, "crlDistributionPoints[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockedGRPCClient{}
			client.On("SignCertificate", mock.Anything, mock.Anything).Return(&protobuf.SignCertificateResponse{}, nil)
			payload := SignCertificatePayload{Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatPem}
			tt.change(&payload)
			response, err := (&Library{client: client}).SignCertificate(context.Background(), payload)
			client.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
			require.ErrorContains(t, err, tt.field)
			require.Nil(t, response)
		})
	}
}

func TestLibrary_SignCertificate(t *testing.T) {
	mockedClient := &mockedGRPCClient{}
	zeroTime := time.Time{}
	currentTime := time.Now()

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoServiceClient
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
					Run(func(args mock.Arguments) {
						id, err := uuid.Parse(args.Get(1).(*protobuf.SignCertificateRequest).GetMetadata().GetId())
						require.NoError(t, err)
						require.Equal(t, uuid.Version(4), id.Version())
						require.Equal(t, uuid.RFC4122, id.Variant())
					}).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatPem},
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
				mockedClient.On("SignCertificate", mock.Anything, mock.MatchedBy(func(req *protobuf.SignCertificateRequest) bool {
					return req.GetMetadata().GetId() == "mocked-id"
				})).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatDer, Metadata: &Metadata{Id: "mocked-id"}},
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
				payload: SignCertificatePayload{Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatPem},
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
				payload: SignCertificatePayload{Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatSign(20)},
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
					Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatPem,
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
					Profile: "Default", CSR: []byte("mocked-csr"), CAPrivateKey: []byte("mocked-key"), CACert: []byte("mocked-cert"), OutputFormat: OutputFormatPem,
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
			t.Cleanup(func() { mockedClient.AssertExpectations(t) })

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
