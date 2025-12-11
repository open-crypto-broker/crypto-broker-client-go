package cryptobrokerclientgo

import (
	"context"

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

// HealthData checks the health status of the server
func (lib *Library) HealthData(ctx context.Context) *HealthDataResponse {
	resp, err := lib.healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return &HealthDataResponse{Status: StatusUnknown}
	}

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
