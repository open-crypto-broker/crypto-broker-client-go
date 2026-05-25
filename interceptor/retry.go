package interceptor

import (
	"context"
	"fmt"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type RetryConfig struct {
	MaxAttempts          uint         `yaml:"maxAttempts"`
	InitialBackoff       string       `yaml:"initialBackoff"`
	BackoffMultiplier    float64      `yaml:"backoffMultiplier"`
	RetryableStatusCodes []codes.Code `yaml:"retryableStatusCodes"`
}

// Create and return retry interceptor
func Retry(config RetryConfig) (grpc.UnaryClientInterceptor, error) {
	initialBackoff, err := time.ParseDuration(config.InitialBackoff)
	if err != nil {
		return nil, fmt.Errorf("parse initial backoff: %w", err)
	}

	interceptor := retry.UnaryClientInterceptor(
		retry.WithMax(config.MaxAttempts),
		retry.WithCodes(config.RetryableStatusCodes...),

		retry.WithBackoff(func(ctx context.Context, attempt uint) time.Duration {
			backoff := float64(initialBackoff)

			for i := uint(0); i < attempt; i++ {
				backoff *= config.BackoffMultiplier
			}

			return time.Duration(backoff)
		}),
	)

	return interceptor, nil
}
