package cryptobrokerclientgo

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc/health/grpc_health_v1"
)

// Status constants
const (
	StatusServing    = "SERVING"
	StatusNotServing = "NOT_SERVING"
	StatusUnknown    = "UNKNOWN"
)

// HealthDataResponse represents the server health status
type HealthDataResponse struct {
	Status string
}

// HealthCheckOptions configures health check retry behavior
type HealthCheckOptions struct {
	MaxRetries int
	RetryDelay time.Duration
	Logger     *log.Logger
}

// DefaultHealthCheckOptions returns default options (60 retries, 1s delay, no logging)
func DefaultHealthCheckOptions() HealthCheckOptions {
	return HealthCheckOptions{
		MaxRetries: 60,
		RetryDelay: 1 * time.Second,
		Logger:     nil,
	}
}

// HealthData checks the health status of the server with default retry options
func (lib *Library) HealthData(ctx context.Context) *HealthDataResponse {
	return lib.HealthDataWithOptions(ctx, DefaultHealthCheckOptions())
}

// HealthDataWithOptions checks the health status with custom retry configuration
func (lib *Library) HealthDataWithOptions(ctx context.Context, opts HealthCheckOptions) *HealthDataResponse {
	for attempt := 1; attempt <= opts.MaxRetries; attempt++ {
		resp, err := lib.healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if err == nil {
			var status string
			switch resp.Status {
			case grpc_health_v1.HealthCheckResponse_SERVING:
				status = StatusServing
			case grpc_health_v1.HealthCheckResponse_NOT_SERVING:
				status = StatusNotServing
			case grpc_health_v1.HealthCheckResponse_UNKNOWN:
				status = StatusUnknown
			default:
				status = StatusUnknown
			}
			return &HealthDataResponse{Status: status}
		}

		if attempt < opts.MaxRetries {
			if opts.Logger != nil {
				opts.Logger.Printf("Could not establish connection. Retrying... (%d/%d)\n", attempt, opts.MaxRetries)
			}
			time.Sleep(opts.RetryDelay)
		}
	}

	// Return UNKNOWN after all retries exhausted (graceful degradation)
	return &HealthDataResponse{Status: StatusUnknown}
}
