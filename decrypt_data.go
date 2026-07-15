package cryptobrokerclientgo

import (
	"context"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

type DecryptDataPayload struct {
	// Profile one of supported by crypto broker cryptogaphic profiles
	Profile string
}

func (lib *Library) DecryptData(ctx context.Context, payload DecryptDataPayload) (*protobuf.DecryptDataResponse, error) {
	return nil, nil
}