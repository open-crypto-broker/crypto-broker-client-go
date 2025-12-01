package cryptobrokerclientgo

import (
	"context"
	"fmt"

	"google.golang.org/grpc/health/grpc_health_v1"
)

// HealthDataResponse represents the server health status
type HealthDataResponse struct {
	Status string
}

// HealthData checks the health status of the server
func (lib *Library) HealthData(ctx context.Context) (*HealthDataResponse, error) {
	resp, err := lib.healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}

	var status string
	switch resp.Status {
	case grpc_health_v1.HealthCheckResponse_SERVING:
		status = "SERVING"
	case grpc_health_v1.HealthCheckResponse_NOT_SERVING:
		status = "NOT_SERVING"
	case grpc_health_v1.HealthCheckResponse_UNKNOWN:
		status = "UNKNOWN"
	default:
		status = "UNKNOWN"
	}

	return &HealthDataResponse{Status: status}, nil
}
