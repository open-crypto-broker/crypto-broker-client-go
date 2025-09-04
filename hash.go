package cryptobrokerclientgo

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// HashingOpts defines all required data that need to be provided in order to invoke hashing.
// The Metadata field is optional and will be created automatically if not provided.
type HashDataPayload struct {
	// Profile one of supported by crypto broker cryptogaphic profiles
	Profile string

	// Input any arbitrary bytes that are meant to be hashed using the hashing algorithm from the profile
	Input []byte

	// (Optional) Metadata to track the request back
	Metadata *Metadata
}

type Metadata struct {
	Id        string
	CreatedAt string
}

// HashData performs logic that results in hashing provided bytes using crypto broker.
// As result it returns hash of provided bytes and non-nil error if any.
func (lib *Library) HashData(ctx context.Context, payload HashDataPayload) (*protobuf.HashResponse, error) {

	// Create the Metadata if not provided
	if payload.Metadata == nil {
		payload.Metadata = &Metadata{
			Id:        uuid.New().String(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	req := &protobuf.HashRequest{
		Profile: payload.Profile,
		Input:   payload.Input,
		Metadata: &protobuf.Metadata{
			Id:        payload.Metadata.Id,
			CreatedAt: payload.Metadata.CreatedAt,
		},
	}

	return lib.client.Hash(ctx, req)
}
