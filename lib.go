package cryptobrokerclientgo

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
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
// Internally it establishes connection to the gRPC server and verifies it or returns non-nil error if any
func NewLibrary(ctx context.Context) (*Library, error) {
	// Create a custom dialer for Unix domain sockets
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", defaultSocketPath)
	}

	// Create gRPC connection using the Unix domain socket
	conn, err := grpc.NewClient("unix://"+defaultSocketPath, grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("could not create gRPC client, err: %w", err)
	}

	lib := &Library{client: protobuf.NewCryptoBrokerClient(conn), conn: conn}
	ctxTimeout, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err = lib.verifyConnection(ctxTimeout); err != nil {
		return nil, fmt.Errorf("could not establish connection to gRPC server, err: %w", err)
	}

	return lib, nil
}

// Close closes established gRPC connection.
func (lib *Library) Close() error {
	if lib.conn == nil {
		return fmt.Errorf("missing connection, nothing to close")
	}

	return lib.conn.Close()
}

// verifyConnection verifies connection between client and server in given context window
func (lib *Library) verifyConnection(ctx context.Context) error {
	lib.conn.Connect()

	state := lib.conn.GetState()
	for {
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return fmt.Errorf("connection is SHUTDOWN")
		}

		if !lib.conn.WaitForStateChange(ctx, state) {
			if ctx.Err() != nil {
				return fmt.Errorf("connectivity did not reach READY before deadline: %w", ctx.Err())
			}

			return fmt.Errorf("connectivity wait aborted")
		}

		state = lib.conn.GetState()
	}
}
