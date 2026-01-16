package cryptobrokerclientgo

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// FakeEndpointPayload defines all required data that need to be provided in order to invoke fake endpoint.
// The Metadata field is optional and will be created automatically if not provided.
type FakeEndpointPayload struct {
	// (Optional) Metadata to track the request back
	Metadata *Metadata
}

// FakeEndpoint performs logic that results in calling fake endpoint on crypto broker.
// As result it returns response message and non-nil error if any.
func (lib *Library) FakeEndpoint(ctx context.Context, payload FakeEndpointPayload) (*protobuf.FakeEndpointResponse, error) {

	// Create the Metadata if not provided
	if payload.Metadata == nil {
		payload.Metadata = &Metadata{
			Id:        uuid.New().String(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	// Convert client TraceContext to protobuf TraceContext
	var protoTraceContext *protobuf.TraceContext
	if payload.Metadata.TraceContext != nil {
		protoTraceContext = &protobuf.TraceContext{
			TraceId:    payload.Metadata.TraceContext.TraceId,
			SpanId:     payload.Metadata.TraceContext.SpanId,
			TraceFlags: payload.Metadata.TraceContext.TraceFlags,
			TraceState: payload.Metadata.TraceContext.TraceState,
		}
	}

	req := &protobuf.FakeEndpointRequest{
		Metadata: &protobuf.Metadata{
			Id:           payload.Metadata.Id,
			CreatedAt:    payload.Metadata.CreatedAt,
			TraceContext: protoTraceContext,
		},
	}

	return lib.client.FakeEndpoint(ctx, req)
}
