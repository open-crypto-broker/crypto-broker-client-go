package cryptobrokerclientgo

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"slices"
)

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

func TestLibrary_HealthData(t *testing.T) {
	mockedClient := &mockedHealthClient{}

	type mockFunc func()
	type fields struct {
		healthClient grpc_health_v1.HealthClient
		conn         *grpc.ClientConn
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name     string
		fields   fields
		mockFunc mockFunc
		args     args
		want     *HealthDataResponse
	}{
		{
			name: "HealthData() succeeds when server returns SERVING",
			fields: fields{
				healthClient: mockedClient,
				conn:         &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &grpc_health_v1.HealthCheckResponse{
					Status: grpc_health_v1.HealthCheckResponse_SERVING,
				}
				mockedClient.On("Check", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
			},
			want: &HealthDataResponse{Status: StatusServing},
		},
		{
			name: "HealthData() succeeds when server returns NOT_SERVING",
			fields: fields{
				healthClient: mockedClient,
				conn:         &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &grpc_health_v1.HealthCheckResponse{
					Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
				}
				mockedClient.On("Check", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
			},
			want: &HealthDataResponse{Status: StatusNotServing},
		},
		{
			name: "HealthData() succeeds when server returns UNKNOWN",
			fields: fields{
				healthClient: mockedClient,
				conn:         &grpc.ClientConn{},
			},
			mockFunc: func() {
				resp := &grpc_health_v1.HealthCheckResponse{
					Status: grpc_health_v1.HealthCheckResponse_UNKNOWN,
				}
				mockedClient.On("Check", mock.Anything, mock.Anything).
					Return(resp, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
			},
			want: &HealthDataResponse{Status: StatusUnknown},
		},
		{
			name: "HealthData() fails when client returns non-nil error",
			fields: fields{
				healthClient: mockedClient,
				conn:         &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("Check", mock.Anything, mock.Anything).
					Return(&grpc_health_v1.HealthCheckResponse{}, errors.New("connection error")).Once()
			},
			args: args{
				ctx: context.TODO(),
			},
			want: &HealthDataResponse{Status: StatusUnknown},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib := &Library{
				healthClient: tt.fields.healthClient,
				conn:         tt.fields.conn,
			}

			tt.mockFunc()

			got := lib.HealthData(tt.args.ctx)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Library.HealthData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkHealthData(b *testing.B) {
	ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
	defer cancel()
	lib, err := NewLibrary(ctx)
	if err != nil {
		b.Fatalf("could not instantiate library, err: %s", err.Error())
	}

	b.Run("HealthData, synchronously", func(b *testing.B) {
		for b.Loop() {
			resp := lib.HealthData(ctx)
			notWantedStatuses := []string{StatusNotServing, StatusUnknown}
			if slices.Contains(notWantedStatuses, resp.Status) {
				b.Errorf("response status is one that is not expected, status: %s", resp.Status)
			}
		}
	})
}

func BenchmarkHealthDataParallel(b *testing.B) {
	b.RunParallel(func(p *testing.PB) {
		ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
		defer cancel()
		lib, err := NewLibrary(ctx)
		if err != nil {
			b.Fatalf("could not instantiate library, err: %s", err.Error())
		}

		for p.Next() {
			resp := lib.HealthData(ctx)
			notWantedStatuses := []string{StatusNotServing, StatusUnknown}
			if slices.Contains(notWantedStatuses, resp.Status) {
				b.Errorf("response status is one that is not expected, status: %s", resp.Status)
			}
		}
	})
}

// TestLibrary_HealthData_E2E tests HealthData against a real server
// This test requires the server to be running (e.g., via `task run`)
func TestLibrary_HealthData_E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lib, err := NewLibrary(ctx)
	if err != nil {
		t.Skipf("Could not connect to server (is it running?): %v", err)
		return
	}
	defer lib.Close()

	response := lib.HealthData(ctx)
	if response == nil {
		t.Error("HealthData() returned nil response")

		return
	}

	validStatuses := []string{StatusServing, StatusNotServing, StatusUnknown}
	if !slices.Contains(validStatuses, response.Status) {
		t.Errorf("HealthData() returned unexpected status: %s", response.Status)
	}

	t.Logf("✅ Server health status: %s", response.Status)
}
