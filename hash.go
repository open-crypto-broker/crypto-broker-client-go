package cryptobrokerclientgo

import (
	"context"
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

type OutputFormatHash protobuf.HashOutputFormat

const (
	OutputFormatRaw OutputFormatHash = OutputFormatHash(protobuf.HashOutputFormat_RAW)
	OutputFormatHex OutputFormatHash = OutputFormatHash(protobuf.HashOutputFormat_HEX)
)

var ErrInvalidHashOutputFormat = fmt.Errorf("invalid hash output format, must be either %v or %v", OutputFormatRaw, OutputFormatHex)

// HashingOpts defines all required data that need to be provided in order to invoke hashing.
// The Metadata field is optional and will be created automatically if not provided.
type HashDataPayload struct {
	// Profile one of supported by crypto broker cryptogaphic profiles
	Profile string

	// Input any arbitrary bytes that are meant to be hashed using the hashing algorithm from the profile
	Input []byte

	// OutputFormat defines the format of the hash output, either raw digest bytes or hex string
	OutputFormat OutputFormatHash

	// (Optional) Metadata to track the request back
	Metadata *Metadata
}

// HashData performs logic that results in hashing provided bytes using crypto broker.
// As result it returns hash of provided bytes and non-nil error if any.
func (lib *Library) HashData(ctx context.Context, payload HashDataPayload) (*protobuf.HashDataResponse, error) {
	req := &protobuf.HashDataRequest{
		Profile:  payload.Profile,
		Input:    payload.Input,
		Metadata: newProtoMetadata(payload.Metadata),
	}

	switch payload.OutputFormat {
	case OutputFormatRaw:
		req.OutputFormat = protobuf.HashOutputFormat_RAW
	case OutputFormatHex:
		req.OutputFormat = protobuf.HashOutputFormat_HEX
	default:
		return nil, ErrInvalidHashOutputFormat
	}

	return lib.client.HashData(ctx, req)
}
