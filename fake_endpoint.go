package cryptobrokerclientgo

import (
	"context"

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
	req := &protobuf.FakeEndpointRequest{
		Metadata: newProtoMetadata(payload.Metadata),
	}

	return lib.development.FakeEndpoint(ctx, req)
}
