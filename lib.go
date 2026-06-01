package cryptobrokerclientgo

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/interceptor"
	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	baseDir           = "/tmp/open-crypto-broker"
	defaultSocketPath = filepath.Join(baseDir, "crypto-broker-server.sock")
)

// Library implements convenient facade to work with crypto broker
type Library struct {
	client       protobuf.CryptoGrpcClient
	development  protobuf.CryptoGrpcDevClient
	healthClient grpc_health_v1.HealthClient
	conn         *grpc.ClientConn
}

// NewLibrary returns pointer to GrpcLibrary instance.
// Internally it establishes connection to the gRPC server,
// configures provided unary interceptors, verifies connectivity,
// or returns non-nil error if any occures.
func NewLibrary(ctx context.Context, configs ...any) (*Library, error) {
	// Create a custom dialer for Unix domain sockets
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", defaultSocketPath)
	}

	// Create default interceptors
	retry, err := retryInterceptor()
	if err != nil {
		return nil, err
	}

	breaker, err := circuitBreakerInterceptor()
	if err != nil {
		return nil, err
	}

	// Apply custom configuration to interceptors
	for _, conf := range configs {
		switch t := conf.(type) {
		case interceptor.RetryConfig:
			retry, err = interceptor.Retry(t)
		case interceptor.CircuitConfig:
			breaker, err = interceptor.CircuitBreaker(t)
		}

		if err != nil {
			return nil, err
		}
	}

	conn, err := grpc.NewClient("unix://"+defaultSocketPath,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			retry,
			breaker,
		),
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
		case connectivity.Connecting, connectivity.TransientFailure, connectivity.Idle:
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

// Create and return default retry interceptor.
func retryInterceptor() (grpc.UnaryClientInterceptor, error) {
	return interceptor.Retry(interceptor.RetryConfig{
		MaxAttempts:          5,
		InitialBackoff:       "500ms",
		BackoffMultiplier:    2.0,
		RetryableStatusCodes: []codes.Code{14, 8, 10},
	})
}

// Create and return default circuit breaker interceptor.
func circuitBreakerInterceptor() (grpc.UnaryClientInterceptor, error) {
	return interceptor.CircuitBreaker(interceptor.CircuitConfig{
		Name:                "crypto-grpc",
		MaxRequests:         3,
		Interval:            "30s",
		Timeout:             "5s",
		ConsecutiveFailures: 3,
		FailureStatusCodes:  []codes.Code{14, 8, 10},
	})
}
