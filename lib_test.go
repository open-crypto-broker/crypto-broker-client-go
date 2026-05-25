package cryptobrokerclientgo

import (
	"context"
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/interceptor"
	"google.golang.org/grpc/codes"
)

func TestNewLibrary(t *testing.T) {
	tests := []struct {
		name         string
		ctxGenerator func() (context.Context, context.CancelFunc)
		wantErr      bool
	}{
		{
			name: "NewLibrary() fails if it cannot connect to server in context window",
			ctxGenerator: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // manually cancel context so that provided context is already done
				return ctx, cancel
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.ctxGenerator()
			defer cancel()

			retryConf := interceptor.RetryConfig{
				MaxAttempts:          5,
				InitialBackoff:       "500ms",
				BackoffMultiplier:    2.0,
				RetryableStatusCodes: []codes.Code{14, 8, 10},
			}

			breakerConf := interceptor.CircuitConfig{
				Name:                "crypto-grpc",
				MaxRequests:         3,
				Interval:            "30s",
				Timeout:             "5s",
				ConsecutiveFailures: 3,
				FailureStatusCodes:  []codes.Code{14, 8, 10},
			}

			_, err := NewLibrary(ctx, retryConf, breakerConf)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLibrary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestLibrary_Close(t *testing.T) {
	lib := &Library{conn: nil}
	err := lib.Close()
	if err == nil {
		t.Fatalf("Library.Close() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing connection") {
		t.Fatalf("Library.Close() error = %q, want it to mention missing connection", err.Error())
	}
}
