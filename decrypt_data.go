package cryptobrokerclientgo

import (
	"context"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

type DecryptDataPayload struct {
	// Profile is one of the cryptographic profiles supported by Crypto Broker.
	Profile string

	// KeySource identifies the key used to decrypt the ciphertext.
	KeySource KeySource

	// Ciphertext is the encrypted data to decrypt.
	Ciphertext []byte

	// Nonce is the AES-GCM nonce used during encryption.
	Nonce []byte

	// AAD is the optional additional authenticated data used during encryption.
	AAD []byte

	// Tag is the AES-GCM authentication tag returned by EncryptData.
	Tag []byte

	// Metadata optionally tracks the request.
	Metadata *Metadata
}

// DecryptData decrypts payload.Ciphertext according to the selected profile.
func (lib *Library) DecryptData(ctx context.Context, payload DecryptDataPayload) (*protobuf.DecryptDataResponse, error) {
	keySource, err := payload.KeySource.toProto()
	if err != nil {
		return nil, err
	}

	return lib.client.DecryptData(ctx, &protobuf.DecryptDataRequest{
		Profile:    payload.Profile,
		KeySource:  keySource,
		Ciphertext: payload.Ciphertext,
		DecryptMetadata: &protobuf.DecryptMetadata{
			Nonce: payload.Nonce,
			Aad:   payload.AAD,
			Tag:   payload.Tag,
		},
		Metadata: newProtoMetadata(payload.Metadata),
	})
}
