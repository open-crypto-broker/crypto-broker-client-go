package interceptor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/sony/gobreaker/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CircuitConfig struct {
	Name                string       `yaml:"name"`
	MaxRequests         uint32       `yaml:"maxRequests"`
	Interval            string       `yaml:"interval"`
	Timeout             string       `yaml:"timeout"`
	ConsecutiveFailures uint32       `yaml:"consecutiveFailures"`
	FailureStatusCodes  []codes.Code `yaml:"failureStatusCodes"`
}

// Create and return circuit breaker interceptor
func CircuitBreaker(config CircuitConfig) (grpc.UnaryClientInterceptor, error) {
	interval, err := time.ParseDuration(config.Interval)
	if err != nil {
		return nil, fmt.Errorf("parse circuit breaker interval: %w", err)
	}

	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parse circuit breaker timeout: %w", err)
	}

	breaker := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name:        config.Name,
		MaxRequests: config.MaxRequests,
		Interval:    interval,
		Timeout:     timeout,

		ReadyToTrip: func(c gobreaker.Counts) bool {
			return c.ConsecutiveFailures >= config.ConsecutiveFailures
		},

		IsSuccessful: func(err error) bool {
			if err == nil {
				return true
			}

			code := status.Code(err)
			for _, c := range config.FailureStatusCodes {
				if c == code {
					return false
				}
			}

			return true
		},

		OnStateChange: func(name string, from, to gobreaker.State) {
			slog.Warn("circuit breaker state changed",
				slog.String("name", name),
				slog.String("from", from.String()),
				slog.String("to", to.String()),
			)
		},
	})

	interceptor := func(
		ctx context.Context,
		method string,
		req any,
		reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		_, err := breaker.Execute(func() (any, error) {
			return nil, invoker(ctx, method, req, reply, cc, opts...)
		})

		return err
	}

	return interceptor, nil
}
