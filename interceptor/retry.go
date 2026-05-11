package interceptor

import (
	"context"
	"fmt"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/stretchr/testify/assert/yaml"
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
func Retry(config []byte) (grpc.UnaryClientInterceptor, error) {
	var cfg RetryConfig

	if err := yaml.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("parse retry config: %w", err)
	}

	initialBackoff, err := time.ParseDuration(cfg.InitialBackoff)
	if err != nil {
		return nil, fmt.Errorf("parse initial backoff: %w", err)
	}

	interceptor := retry.UnaryClientInterceptor(
		retry.WithMax(cfg.MaxAttempts),
		retry.WithCodes(cfg.RetryableStatusCodes...),

		retry.WithBackoff(func(ctx context.Context, attempt uint) time.Duration {
			backoff := float64(initialBackoff)

			for i := uint(0); i < attempt; i++ {
				backoff *= cfg.BackoffMultiplier
			}

			return time.Duration(backoff)
		}),
	)

	return interceptor, nil
}
