package cryptobrokerclientgo

import (
	"context"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// VerifyDataPayload contains a payload, signature, and verification configuration.
type VerifyDataPayload struct {
	Profile         string
	KeySource       SignKeySource
	Input           []byte
	Signature       []byte
	SignatureFormat *SignatureFormat
	Metadata        *Metadata
}

// VerifyData verifies payload.Signature against payload.Input according to the selected profile.
func (lib *Library) VerifyData(ctx context.Context, payload VerifyDataPayload) (*protobuf.VerifyDataResponse, error) {
	keySource, err := payload.KeySource.toProto()
	if err != nil {
		return nil, err
	}

	return lib.client.VerifyData(ctx, &protobuf.VerifyDataRequest{
		Profile:         payload.Profile,
		KeySource:       keySource,
		Input:           payload.Input,
		Signature:       payload.Signature,
		SignatureFormat: payload.SignatureFormat.toProto(),
		Metadata:        newProtoMetadata(payload.Metadata),
	})
}
