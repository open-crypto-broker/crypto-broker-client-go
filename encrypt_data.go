package cryptobrokerclientgo

import (
	"context"
	"errors"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

var ErrInvalidKeySource = errors.New("exactly one of raw key or key ID must be provided")

// KeySource identifies caller-managed raw key material or a broker-managed key.
// Exactly one field must be populated.
type KeySource struct {
	KeyID  string
	RawKey []byte
}

type EncryptDataPayload struct {
	// Profile is one of the cryptographic profiles supported by Crypto Broker.
	Profile string

	// KeySource identifies the key used to encrypt the plaintext.
	KeySource KeySource

	// Plaintext is the data to encrypt.
	Plaintext []byte

	// Nonce is the AES-GCM nonce required by caller-managed encryption profiles.
	Nonce []byte

	// AAD is optional additional authenticated data.
	AAD []byte

	// Metadata optionally tracks the request.
	Metadata *Metadata
}

// EncryptData encrypts payload.Plaintext according to the selected profile.
func (lib *Library) EncryptData(ctx context.Context, payload EncryptDataPayload) (*protobuf.EncryptDataResponse, error) {
	keySource, err := payload.KeySource.toProto()
	if err != nil {
		return nil, err
	}

	return lib.client.EncryptData(ctx, &protobuf.EncryptDataRequest{
		Profile:   payload.Profile,
		KeySource: keySource,
		Plaintext: payload.Plaintext,
		EncryptMetadata: &protobuf.EncryptMetadata{
			Nonce: payload.Nonce,
			Aad:   payload.AAD,
		},
		Metadata: newProtoMetadata(payload.Metadata),
	})
}

func (source KeySource) toProto() (*protobuf.KeySource, error) {
	hasKeyID := source.KeyID != ""
	hasRawKey := len(source.RawKey) != 0
	if hasKeyID == hasRawKey {
		return nil, ErrInvalidKeySource
	}
	if hasKeyID {
		return &protobuf.KeySource{Source: &protobuf.KeySource_KeyId{KeyId: source.KeyID}}, nil
	}

	return &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: source.RawKey}}, nil
}
