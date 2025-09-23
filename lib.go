package cryptobrokerclientgo

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"path/filepath"
	"time"
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
	if err = lib.verifyConnection(ctx, 60, 1*time.Second); err != nil {
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

// verifyConnection verifies connection to the gRPC server.
// It returns non-nil error if connection cannot be established in the given context window.
func (lib *Library) verifyConnection(ctx context.Context, retries uint, delay time.Duration) error {
	var errLatest error

	// Loop until connection is established in (retries * delay) time window or context is cancelled
	for i := 0; i < int(retries); i++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled, err: %w", ctx.Err())
		default:

			// Predefined timeout for single request to avoid blocking the context window
			ctxRequest, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if _, err := lib.client.Hash(ctxRequest, &protobuf.HashRequest{
				Metadata: &protobuf.Metadata{Id: uuid.New().String(), CreatedAt: time.Now().UTC().Format(time.RFC3339)},
				Input:    []byte("Hello world"),
				Profile:  "Default",
			}); err != nil {
				errLatest = err
				time.Sleep(delay)

				continue
			}

			return nil
		}
	}

	return errLatest
}
