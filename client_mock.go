package cryptobrokerclientgo

import (
	"context"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Mocked client for grpc service
type mockedGRPCClient struct {
	mock.Mock
}

func (m *mockedGRPCClient) HashData(ctx context.Context, in *protobuf.HashDataRequest, opts ...grpc.CallOption) (*protobuf.HashDataResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*protobuf.HashDataResponse), args.Error(1)
}

func (m *mockedGRPCClient) SignCertificate(ctx context.Context, in *protobuf.SignCertificateRequest, opts ...grpc.CallOption) (*protobuf.SignCertificateResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*protobuf.SignCertificateResponse), args.Error(1)
}

// Mocked client for grpc dev service
type mockedGRPCDevClient struct {
	mock.Mock
}

func (m *mockedGRPCDevClient) Benchmark(ctx context.Context, in *protobuf.BenchmarkRequest, opts ...grpc.CallOption) (*protobuf.BenchmarkResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*protobuf.BenchmarkResponse), args.Error(1)
}

func (m *mockedGRPCDevClient) FakeEndpoint(ctx context.Context, in *protobuf.FakeEndpointRequest, opts ...grpc.CallOption) (*protobuf.FakeEndpointResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*protobuf.FakeEndpointResponse), args.Error(1)
}

// Mocked client for health service
type mockedHealthClient struct {
	mock.Mock
}

func (m *mockedHealthClient) Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest, opts ...grpc.CallOption) (*grpc_health_v1.HealthCheckResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*grpc_health_v1.HealthCheckResponse), args.Error(1)
}

func (m *mockedHealthClient) Watch(ctx context.Context, in *grpc_health_v1.HealthCheckRequest, opts ...grpc.CallOption) (grpc_health_v1.Health_WatchClient, error) {
	args := m.Called(ctx, in)
	return nil, args.Error(1)
}

func (m *mockedHealthClient) List(ctx context.Context, in *grpc_health_v1.HealthListRequest, opts ...grpc.CallOption) (*grpc_health_v1.HealthListResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*grpc_health_v1.HealthListResponse), args.Error(1)
}
