package interceptor

import (
	"context"
	"testing"

	"github.com/lithammer/dedent"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRetry_Retries(t *testing.T) {
	config := dedent.Dedent(`
    maxAttempts: 3
    initialBackoff: 1ms
    backoffMultiplier: 1
    retryableStatusCodes:
      - 14
	`)

	interceptor, err := Retry([]byte(config))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attempts := 0

	invoker := func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		attempts++
		return status.Error(codes.Unavailable, "temporary failure")
	}

	_ = interceptor(context.Background(), "/test.Service/Test", nil, nil, nil, invoker)

	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}
