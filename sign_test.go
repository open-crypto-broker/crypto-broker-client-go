package cryptobrokerclientgo

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
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
		opts    []func(*optionsSignCertificate)
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
			name: "SignCertificate() succeeds when client returns response without error and PEM encoding is used",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.SignResponse{SignedCertificate: "MIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQwgYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAoBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5MTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQIEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAxMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuzGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjfpxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwRmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0Ws4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8="}
				mockedClient.On("Sign", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{},
				opts:    []func(*optionsSignCertificate){WithPEMEncoding()},
			},
			want:    &protobuf.SignResponse{SignedCertificate: "-----BEGIN CERTIFICATE-----\nMIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQw\ngYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0\nLU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAo\nBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5\nMTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAx\nMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuz\nGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjf\npxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMC\nBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW\ngBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwR\nmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0W\ns4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8=\n-----END CERTIFICATE-----\n"},
			wantErr: false,
		},
		{
			name: "SignCertificate() succeeds when client returns response without error and PEM encoding is used (by default)",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.SignResponse{SignedCertificate: "MIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQwgYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAoBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5MTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQIEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAxMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuzGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjfpxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwRmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0Ws4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8="}
				mockedClient.On("Sign", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{},
				opts:    []func(*optionsSignCertificate){},
			},
			want:    &protobuf.SignResponse{SignedCertificate: "-----BEGIN CERTIFICATE-----\nMIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQw\ngYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0\nLU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAo\nBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5\nMTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAx\nMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuz\nGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjf\npxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMC\nBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW\ngBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwR\nmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0W\ns4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8=\n-----END CERTIFICATE-----\n"},
			wantErr: false,
		},
		{
			name: "SignCertificate() succeeds when client returns response without error and B64 encoding is used",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.SignResponse{SignedCertificate: "MIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQwgYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAoBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5MTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQIEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAxMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuzGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjfpxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwRmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0Ws4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8="}
				mockedClient.On("Sign", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: SignCertificatePayload{},
				opts:    []func(*optionsSignCertificate){WithBase64Encoding()},
			},
			want:    &protobuf.SignResponse{SignedCertificate: "MIICaDCCAe6gAwIBAgIUHereBfzbYtrts/fQz5amVRJeNkwwCgYIKoZIzj0EAwQwgYYxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6YXRpb24tQ0ExKjAoBgNVBAMMIVRlc3QtT3JnYW5pemF0aW9uLUludGVybWVkaWF0ZS1DQTAeFw0yNTA5MTYxMTM1NTFaFw0yNjA5MTYxMjM1NTFaMEwxCzAJBgNVBAYTAkRFMQswCQYDVQQIEwJCQTEMMAoGA1UEChMDU0FQMQ8wDQYDVQQDEwZNeUNlcnQxETAPBgNVBAUTCDAxMjM0NTU2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgLWqYJmgsXLUJLta6oIOykuzGNz76VMZj+wcfb9+MZA5A/WSfPVk9/JigQOfF49JcOI1Wb+gIfq1TNAkK/xOMTjfpxXeYglrFW/e278Q3TbYvhEHI3kOgIUJDbhSvRn/o1YwVDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT3KuJBMgQEcYrmI1TyGOb0P2/P3zAKBggqhkjOPQQDBANoADBlAjEAysok6BwRmNOrt4UeBpw2NF87xuoek/dF9lXOalpXtp+cXHjgigcWmguT48ve29CmAjBNir0Ws4SQBr9PwtCbILoLwMihfkqIjjib63+q30YpW6nghOlKv2iI1Yobd05HBH8="},
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

			got, err := lib.SignCertificate(tt.args.ctx, tt.args.payload, tt.args.opts...)
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

func BenchmarkSignCertificate(b *testing.B) {
	ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
	defer cancel()
	lib, err := NewLibrary(ctx)
	if err != nil {
		b.Fatalf("could not instantiate library, err: %s", err.Error())
	}

	b.Run("SignCertificate, profile Default, synchronously", func(b *testing.B) {
		for b.Loop() {
			_, err := lib.SignCertificate(ctx, SignCertificatePayload{
				Profile: "Default",
				CSR: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBXzCCAQUCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQ48h5W8DkBTRbwfB2tHPKi3I4kzgcPuMPcOlh7C8vSiV13UszH
BiOloPCcl7+0hz1D8difRsdeya9sKLK2qR2soAAwCgYIKoZIzj0EAwIDSAAwRQIg
T2sYmyQws9zTgPv0HJcD/q5Uds5DmFoAM5D0LANNU8sCIQDT05wfvy7UEjKO2nX5
Bg9SEosO1TISv45Llcl4m7wkFQ==
-----END CERTIFICATE REQUEST-----
`),
				CAPrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBGW8UiwRuSxxS/Rj5u
FRQvQo7miZG+e/f8veaUcMv5JM5mNi61GtzzQ1hiVArskxChZANiAATidJfbi35A
m+uXmcYKRsOOoi7YqqpQAI+RI8hMn66l2qVaTDWRlAI87u9iw1pvRoGH3nNrsiig
8nCxDr7mPzitAmMeBkFBZaTCFBstVZIDgrv3oZifwRvIaUY8Ppv7ntg=
-----END PRIVATE KEY-----
`),
				CACert: []byte(`-----BEGIN CERTIFICATE-----
MIICoTCCAiegAwIBAgIUZv687AKMDfhBzPhtYqY841Zshf0wCgYIKoZIzj0EAwQw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMH4xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlh
MRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdh
bml6YXRpb24tQ0ExIjAgBgNVBAMMGVRlc3QtT3JnYW5pemF0aW9uLVJvb3QtQ0Ew
djAQBgcqhkjOPQIBBgUrgQQAIgNiAATidJfbi35Am+uXmcYKRsOOoi7YqqpQAI+R
I8hMn66l2qVaTDWRlAI87u9iw1pvRoGH3nNrsiig8nCxDr7mPzitAmMeBkFBZaTC
FBstVZIDgrv3oZifwRvIaUY8Ppv7ntijZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEw
DgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTiB5J+O82fGVW8oYbKI2lxR9yqfjAf
BgNVHSMEGDAWgBTiB5J+O82fGVW8oYbKI2lxR9yqfjAKBggqhkjOPQQDBANoADBl
AjAaaXME5CL0R65/hD+f5Zn5zRbzsIw1w88EnkgIw44kRd7M5N0HORiEGh+6jlt5
PsUCMQDEiwry2XAcLFZvxLfCmia4Qobs/EkaZVQ1fCcs6j3Z/mnslUJyobaIkDPa
G5MLQWA=
-----END CERTIFICATE-----`),
			})
			if err != nil {
				b.Errorf("SignCertificate returned non-nil err: %s", err)
			}
		}
	})
}

func BenchmarkSignCertificateParallel(b *testing.B) {

	b.Run("SignCertificate, profile Default, parallel, fixed data", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
			defer cancel()
			lib, err := NewLibrary(ctx)
			if err != nil {
				b.Fatalf("could not instantiate library, err: %s", err.Error())
			}

			for pb.Next() {
				_, err := lib.SignCertificate(ctx, SignCertificatePayload{
					Profile: "Default",
					CSR: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBXzCCAQUCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQ48h5W8DkBTRbwfB2tHPKi3I4kzgcPuMPcOlh7C8vSiV13UszH
BiOloPCcl7+0hz1D8difRsdeya9sKLK2qR2soAAwCgYIKoZIzj0EAwIDSAAwRQIg
T2sYmyQws9zTgPv0HJcD/q5Uds5DmFoAM5D0LANNU8sCIQDT05wfvy7UEjKO2nX5
Bg9SEosO1TISv45Llcl4m7wkFQ==
-----END CERTIFICATE REQUEST-----
`),
					CAPrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBGW8UiwRuSxxS/Rj5u
FRQvQo7miZG+e/f8veaUcMv5JM5mNi61GtzzQ1hiVArskxChZANiAATidJfbi35A
m+uXmcYKRsOOoi7YqqpQAI+RI8hMn66l2qVaTDWRlAI87u9iw1pvRoGH3nNrsiig
8nCxDr7mPzitAmMeBkFBZaTCFBstVZIDgrv3oZifwRvIaUY8Ppv7ntg=
-----END PRIVATE KEY-----
`),
					CACert: []byte(`-----BEGIN CERTIFICATE-----
MIICoTCCAiegAwIBAgIUZv687AKMDfhBzPhtYqY841Zshf0wCgYIKoZIzj0EAwQw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMH4xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlh
MRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdh
bml6YXRpb24tQ0ExIjAgBgNVBAMMGVRlc3QtT3JnYW5pemF0aW9uLVJvb3QtQ0Ew
djAQBgcqhkjOPQIBBgUrgQQAIgNiAATidJfbi35Am+uXmcYKRsOOoi7YqqpQAI+R
I8hMn66l2qVaTDWRlAI87u9iw1pvRoGH3nNrsiig8nCxDr7mPzitAmMeBkFBZaTC
FBstVZIDgrv3oZifwRvIaUY8Ppv7ntijZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEw
DgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTiB5J+O82fGVW8oYbKI2lxR9yqfjAf
BgNVHSMEGDAWgBTiB5J+O82fGVW8oYbKI2lxR9yqfjAKBggqhkjOPQQDBANoADBl
AjAaaXME5CL0R65/hD+f5Zn5zRbzsIw1w88EnkgIw44kRd7M5N0HORiEGh+6jlt5
PsUCMQDEiwry2XAcLFZvxLfCmia4Qobs/EkaZVQ1fCcs6j3Z/mnslUJyobaIkDPa
G5MLQWA=
-----END CERTIFICATE-----`),
				})
				if err != nil {
					b.Errorf("SignCertificate returned non-nil err: %s", err)
				}
			}
		})
	})

	b.Run("SignCertificate, profile Default, parallel, referenced data", func(b *testing.B) {
		pk, err := os.ReadFile("../crypto-broker-deployment/testing/certificates/test-ca/root-CA-ecdsa-private-key.pem")
		if err != nil {
			b.Fatalf("could not read private key, err: %s", err.Error())
		}
		cert, err := os.ReadFile("../crypto-broker-deployment/testing/certificates/test-ca/root-CA-ecdsa.pem")
		if err != nil {
			b.Fatalf("could not read certificate, err: %s", err.Error())
		}
		csr, err := os.ReadFile("../crypto-broker-deployment/testing/certificates/test-csr/test-client.csr")
		if err != nil {
			b.Fatalf("could not read certificate, err: %s", err.Error())
		}

		b.RunParallel(func(pb *testing.PB) {
			ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
			defer cancel()
			lib, err := NewLibrary(ctx)
			if err != nil {
				b.Fatalf("could not instantiate library, err: %s", err.Error())
			}

			for pb.Next() {
				_, err := lib.SignCertificate(ctx, SignCertificatePayload{
					Profile:      "Default",
					CSR:          csr,
					CAPrivateKey: pk,
					CACert:       cert,
				})
				if err != nil {
					b.Errorf("SignCertificate returned non-nil err: %s", err)
				}
			}
		})
	})

}
