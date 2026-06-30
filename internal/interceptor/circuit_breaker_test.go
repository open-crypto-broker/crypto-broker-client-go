package interceptor

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCircuitBreaker_StateChanges(t *testing.T) {
	cfg := CircuitConfig{
		Name:                "test",
		MaxRequests:         2,
		Interval:            "30s",
		Timeout:             "1ms",
		ConsecutiveFailures: 2,
		FailureStatusCodes:  []codes.Code{14},
	}

	interceptor, err := CircuitBreaker(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()

	fail :=
		func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return status.Error(codes.Unavailable, "failure")
		}

	success :=
		func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return nil
		}

	// CLOSED:
	// first failure, circuit is still closed.
	err = interceptor(ctx, "circuit_breaker", nil, nil, nil, fail)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected unavailable error, got %v", err)
	}

	// CLOSED -> OPEN:
	// second consecutive failure opens the circuit.
	err = interceptor(ctx, "circuit_breaker", nil, nil, nil, fail)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected unavailable error, got %v", err)
	}

	// OPEN:
	// request is rejected immediately.
	err = interceptor(ctx, "circuit_breaker", nil, nil, nil, success)
	if err == nil {
		t.Fatal("expected open circuit error")
	}

	// OPEN -> HALF-OPEN:
	// timeout passed, trial requests are allowed.
	time.Sleep(2 * time.Millisecond)

	// HALF-OPEN:
	// first successful trial request is not enough to close circuit.
	err = interceptor(ctx, "circuit_breaker", nil, nil, nil, success)
	if err != nil {
		t.Fatalf("expected first half-open success, got %v", err)
	}

	// HALF-OPEN -> CLOSED:
	// maxRequests=2, so second successful trial request closes circuit.
	err = interceptor(ctx, "circuit_breaker", nil, nil, nil, success)
	if err != nil {
		t.Fatalf("expected second half-open success, got %v", err)
	}

	// CLOSED:
	// normal request is allowed again.
	err = interceptor(ctx, "circuit_breaker", nil, nil, nil, success)
	if err != nil {
		t.Fatalf("expected closed circuit success, got %v", err)
	}
}
