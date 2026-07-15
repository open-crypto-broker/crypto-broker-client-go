package cryptobrokerclientgo

import (
	"context"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

type EncryptDataPayload struct {
	// Profile one of supported by crypto broker cryptogaphic profiles
	Profile string
}

func (lib *Library) EncryptData(ctx context.Context, payload EncryptDataPayload) (*protobuf.EncryptDataResponse, error) {
	return nil, nil
}