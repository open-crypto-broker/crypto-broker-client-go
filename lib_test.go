package cryptobrokerclientgo

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"google.golang.org/grpc"
)

func TestNewLibrary(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "NewLibrary() always succeeds while invoked in system supporing unix domain sockets",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLibrary()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLibrary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestLibrary_Close(t *testing.T) {
	workingLib, err := NewLibrary()
	if err != nil {
		t.Errorf("could not instantiate working instance of library, err: %s", err)

		return
	}

	type fields struct {
		client protobuf.CryptoBrokerClient
		conn   *grpc.ClientConn
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Close() succeeds on correctly initialized Library",
			fields: fields{
				client: &mockedCryptoBrokerClient{},
				conn:   workingLib.conn,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib := &Library{
				client: tt.fields.client,
				conn:   tt.fields.conn,
			}
			if err := lib.Close(); (err != nil) != tt.wantErr {
				t.Errorf("Library.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
