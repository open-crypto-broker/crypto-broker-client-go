package cryptobrokerclientgo

import (
	"context"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

func TestLibrary_FakeEndpoint(t *testing.T) {
	mockedClient := &mockedGRPCClient{}

	type mockFunc func()
	type fields struct {
		client protobuf.CryptoGrpcClient
		conn   *grpc.ClientConn
	}
	type args struct {
		ctx     context.Context
		payload FakeEndpointPayload
	}

	tests := []struct {
		name     string
		fields   fields
		mockFunc mockFunc
		args     args
		wantErr  bool
	}{
		{
			name: "FakeEndpoint() creates Metadata when payload.Metadata is nil",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("FakeEndpoint", mock.Anything, mock.MatchedBy(func(req *protobuf.FakeEndpointRequest) bool {
					if req == nil || req.GetMetadata() == nil {
						return false
					}
					if req.GetMetadata().GetId() == "" || req.GetMetadata().GetCreatedAt() == "" {
						return false
					}
					if _, err := time.Parse(time.RFC3339, req.GetMetadata().GetCreatedAt()); err != nil {
						return false
					}
					return req.GetMetadata().GetTraceContext() == nil
				})).Return(&protobuf.FakeEndpointResponse{}, nil).Once()
			},
			args: args{
				ctx:     context.TODO(),
				payload: FakeEndpointPayload{Metadata: nil},
			},
			wantErr: false,
		},
		{
			name: "FakeEndpoint() maps TraceContext fields when provided",
			fields: fields{
				client: mockedClient,
				conn:   &grpc.ClientConn{},
			},
			mockFunc: func() {
				mockedClient.On("FakeEndpoint", mock.Anything, mock.MatchedBy(func(req *protobuf.FakeEndpointRequest) bool {
					if req == nil || req.GetMetadata() == nil || req.GetMetadata().GetTraceContext() == nil {
						return false
					}
					tc := req.GetMetadata().GetTraceContext()
					return tc.GetTraceId() == "trace" &&
						tc.GetSpanId() == "span" &&
						tc.GetTraceFlags() == "01" &&
						tc.GetTraceState() == "state" &&
						tc.GetCorrelationId() == "corr"
				})).Return(&protobuf.FakeEndpointResponse{}, nil).Once()
			},
			args: args{
				ctx: context.TODO(),
				payload: FakeEndpointPayload{
					Metadata: &Metadata{
						Id:        "id-123",
						CreatedAt: "2026-01-01T00:00:00Z",
						TraceContext: &TraceContext{
							TraceId:       "trace",
							SpanId:        "span",
							TraceFlags:    "01",
							TraceState:    "state",
							CorrelationId: "corr",
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib := &Library{
				client: tt.fields.client,
				conn:   tt.fields.conn,
			}

			tt.mockFunc()

			_, err := lib.FakeEndpoint(tt.args.ctx, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Library.FakeEndpoint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
