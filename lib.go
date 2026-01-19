package cryptobrokerclientgo

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
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

// retryPolicy defines the gRPC retry configuration
const retryPolicy = `{
	"methodConfig": [{
		"name": [{"service": ""}],
		"waitForReady": true,
		"retryPolicy": {
			"maxAttempts": 5,
			"initialBackoff": "1s",
			"maxBackoff": "10s",
			"backoffMultiplier": 2.0,
			"retryableStatusCodes": ["UNAVAILABLE", "RESOURCE_EXHAUSTED", "ABORTED"]
		}
	}]
}`

// Library implements convenient facade to work with crypto broker
type Library struct {
	client       protobuf.CryptoGrpcClient
	healthClient grpc_health_v1.HealthClient
	conn         *grpc.ClientConn
}

// NewLibrary returns pointer to GrpcLibrary instance.
// Internally it establishes connection to the gRPC server and verifies it or returns non-nil error if any
func NewLibrary(ctx context.Context) (*Library, error) {
	// Create a custom dialer for Unix domain sockets
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", defaultSocketPath)
	}

	var unaryInterceptors []grpc.UnaryClientInterceptor
	conn, err := grpc.NewClient("unix://"+defaultSocketPath,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(retryPolicy),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create gRPC client, err: %w", err)
	}

	lib := &Library{
		client:       protobuf.NewCryptoGrpcClient(conn),
		healthClient: grpc_health_v1.NewHealthClient(conn),
		conn:         conn,
	}
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
