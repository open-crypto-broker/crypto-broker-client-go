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

func TestLibrary_BenchmarkData(t *testing.T) {
	mockedClient := &mockedGRPCClient{}

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoGrpcClient
		conn   *grpc.ClientConn
	}
	type args struct {
		ctx     context.Context
		payload BenchmarkDataPayload
	}
	tests := []struct {
		name     string
		fields   fields
		mockFunc mockFunc
		args     args
		want     *BenchmarkResults
		wantErr  bool
	}{
		{
			name: "BenchmarkData() succeeds when client returns response without error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.BenchmarkResponse{BenchmarkResults: `{"results":[{"name":"BenchmarkLibraryNative_HashSHA3_256","avgTime":12345},{"name":"BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_RSA4096","avgTime":67890}]}`}
				mockedClient.On("Benchmark", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: BenchmarkDataPayload{},
			},
			want: &BenchmarkResults{Results: []BenchmarkResult{
				{Name: "BenchmarkLibraryNative_HashSHA3_256", AvgTime: 12345},
				{Name: "BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_RSA4096", AvgTime: 67890},
			}},
			wantErr: false,
		},
		{
			name: "BenchmarkData() fails when client returns non-nil error",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("Benchmark", mock.Anything, mock.Anything).
					Return(&protobuf.BenchmarkResponse{}, errors.New("some error")).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: BenchmarkDataPayload{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "BenchmarkData() fails when server returns malformed JSON string",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &protobuf.BenchmarkResponse{BenchmarkResults: `{malformed json}`}
				mockedClient.On("Benchmark", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: BenchmarkDataPayload{},
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

			got, err := lib.BenchmarkData(tt.args.ctx, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("Library.BenchmarkData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Library.BenchmarkData() = %v, want %v", got, tt.want)
			}
		})
	}
}
