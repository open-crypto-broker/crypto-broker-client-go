package cryptobrokerclientgo

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultSocketPath defines default full OS path to socket file.
// Such path differs between platforms (linux / windows).
// It consist of OS temporary directory followed by fixed socket name.
//
// Please see os.TempDir() doc to see how OS temporary dir is discovered.
var (
	baseDir           = "/tmp"
	defaultSocketPath = filepath.Join(baseDir, "cryptobroker.sock")
)

// Library implements convenient facade to work with crypto broker
type Library struct {
	client protobuf.CryptoBrokerClient
	conn   *grpc.ClientConn
}

// NewLibrary returns pointer to GrpcLibrary instance.
// Internally it establishes connection to the gRPC server or returns non-nil error if any
func NewLibrary() (*Library, error) {
	// Create a custom dialer for Unix domain sockets
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", defaultSocketPath)
	}

	// Create gRPC connection using the Unix domain socket
	conn, err := grpc.NewClient("unix://"+defaultSocketPath, grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("could not connect to gRPC server, err: %w", err)
	}

	return &Library{
		client: protobuf.NewCryptoBrokerClient(conn),
		conn:   conn,
	}, nil
}

// Close closes established gRPC connection.
func (lib *Library) Close() error {
	if lib.conn == nil {
		return fmt.Errorf("missing connection, nothing to close")
	}

	return lib.conn.Close()
}
