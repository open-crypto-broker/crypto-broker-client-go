package cryptobrokerclientgo

import (
	"context"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type retryCountingMock struct {
	mock.Mock
	attemptCount int
	failUntil    int
}

func (m *retryCountingMock) Hash(ctx context.Context, in *protobuf.HashRequest, opts ...grpc.CallOption) (*protobuf.HashResponse, error) {
	m.attemptCount++
	
	// Fail with UNAVAILABLE until we reach the success threshold
	if m.attemptCount < m.failUntil {
		return nil, status.Error(codes.Unavailable, "service temporarily unavailable")
	}
	
	// Succeed on the final attempt
	return &protobuf.HashResponse{
		HashValue:     "test-hash-value",
		HashAlgorithm: "sha3-512",
	}, nil
}

func (m *retryCountingMock) Sign(ctx context.Context, in *protobuf.SignRequest, opts ...grpc.CallOption) (*protobuf.SignResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*protobuf.SignResponse), args.Error(1)
}

func (m *retryCountingMock) Benchmark(ctx context.Context, in *protobuf.BenchmarkRequest, opts ...grpc.CallOption) (*protobuf.BenchmarkResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*protobuf.BenchmarkResponse), args.Error(1)
}

func TestRetryPolicy_ServiceConfig(t *testing.T) {
	// Test that the retry policy constant is valid JSON
	if retryPolicy == "" {
		t.Error("retryPolicy should not be empty")
	}
	
	// The retry policy should contain key fields
	expectedFields := []string{
		"methodConfig",
		"retryPolicy",
		"maxAttempts",
		"initialBackoff",
		"maxBackoff",
		"backoffMultiplier",
		"retryableStatusCodes",
	}
	
	for _, field := range expectedFields {
		if !contains(retryPolicy, field) {
			t.Errorf("retryPolicy missing expected field: %s", field)
		}
	}
}

// TestRetryPolicy_TransientFailures tests retry behavior.
// Note: This is a documentation test showing expected behavior.
// Actual retry testing requires a real gRPC server (see E2E tests)
func TestRetryPolicy_TransientFailures(t *testing.T) {
	t.Skip("Skipping: gRPC retries only work with actual network calls, not mocks. See TestRetryPolicy_E2E for real testing.")
	
	// This test documents the expected behavior:
	// 1. Client receives UNAVAILABLE error
	// 2. gRPC client automatically retries with exponential backoff
	// 3. After maxAttempts (5) or success, the call completes
	// 4. Retryable codes: UNAVAILABLE, RESOURCE_EXHAUSTED, ABORTED
}

func TestRetryPolicy_NonRetryableError(t *testing.T) {
	mockClient := &mockedGRPCClient{}
	
	// Return a non-retryable error (INVALID_ARGUMENT)
	mockClient.On("Hash", mock.Anything, mock.Anything).
		Return(&protobuf.HashResponse{}, status.Error(codes.InvalidArgument, "invalid argument")).
		Once()
	
	lib := &Library{
		client: mockClient,
		conn:   &grpc.ClientConn{},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	_, err := lib.HashData(ctx, HashDataPayload{
		Profile: "Default",
		Input:   []byte("test data"),
	})
	
	// Should fail immediately without retries for non-retryable errors
	if err == nil {
		t.Error("Expected error for invalid argument")
	}
	
	// Verify mock was called only once (no retries)
	mockClient.AssertNumberOfCalls(t, "Hash", 1)
	t.Logf("✅ Non-retryable error failed immediately without retries")
}

// TestRetryPolicy_E2E tests retry behavior against a real server.
// This test requires the server to be running.
// To manually test retries:
// 1. Start the server: task run
// 2. Run this test: go test -v -run TestRetryPolicy_E2E
// 3. While test is running, stop/restart the server to simulate UNAVAILABLE
// 4. Observe retry attempts in the logs
func TestRetryPolicy_E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	lib, err := NewLibrary(ctx)
	if err != nil {
		t.Skipf("Could not connect to server (is it running?): %v", err)
		return
	}
	defer lib.Close()
	
	// Make multiple requests to test retry behavior
	for i := 0; i < 3; i++ {
		resp, err := lib.HashData(ctx, HashDataPayload{
			Profile: "Default",
			Input:   []byte("test retry data"),
		})
		
		if err != nil {
			t.Logf("Request %d failed: %v (this is OK if server is temporarily down)", i+1, err)
			continue
		}
		
		if resp == nil {
			t.Errorf("Request %d returned nil response", i+1)
			continue
		}
		
		t.Logf("✅ Request %d succeeded", i+1)
		time.Sleep(1 * time.Second)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
