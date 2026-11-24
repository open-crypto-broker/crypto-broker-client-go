package cryptobrokerclientgo

import (
	"context"
	"errors"

	protobuf "github.com/open-crypto-broker/crypto-broker-client-go/internal/gen/cryptobroker/v1"
)

var ErrInvalidSignKeySource = errors.New("exactly one of a single key or component keys must be provided")

// SignKeySource identifies the key material used to create or verify a signature.
// Exactly one field must be populated.
type SignKeySource struct {
	Single        *KeySource
	ComponentKeys []KeySource
}

// SignatureFormat controls the signature encoding requested from the broker.
type SignatureFormat int32

const (
	SignatureFormatRaw SignatureFormat = SignatureFormat(protobuf.SignatureFormat_SIGNATURE_FORMAT_RAW)
	SignatureFormatDER SignatureFormat = SignatureFormat(protobuf.SignatureFormat_SIGNATURE_FORMAT_DER)
	SignatureFormatPEM SignatureFormat = SignatureFormat(protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM)
	SignatureFormatCMS SignatureFormat = SignatureFormat(protobuf.SignatureFormat_SIGNATURE_FORMAT_CMS)
)

// SignDataPayload contains an arbitrary payload and its signing configuration.
// Raw private keys in KeySource must be PKCS#8 DER encoded.
type SignDataPayload struct {
	Profile         string
	KeySource       SignKeySource
	Input           []byte
	SignatureFormat *SignatureFormat
	Metadata        *Metadata
}

// SignData signs payload.Input according to the selected profile.
func (lib *Library) SignData(ctx context.Context, payload SignDataPayload) (*protobuf.SignDataResponse, error) {
	keySource, err := payload.KeySource.toProtoWithRawKeyEncoder(privateKeyDER)
	if err != nil {
		return nil, err
	}
	if err := validateSignDataPayload(payload); err != nil {
		return nil, err
	}

	return lib.client.SignData(ctx, &protobuf.SignDataRequest{
		Profile:         payload.Profile,
		KeySource:       keySource,
		Input:           payload.Input,
		SignatureFormat: payload.SignatureFormat.toProto(),
		Metadata:        newProtoMetadata(payload.Metadata),
	})
}

func (source SignKeySource) toProtoWithRawKeyEncoder(encodeRawKey func([]byte) ([]byte, error)) (*protobuf.SignKeySource, error) {
	hasSingle := source.Single != nil
	hasComponents := len(source.ComponentKeys) != 0
	if hasSingle == hasComponents {
		return nil, ErrInvalidSignKeySource
	}

	if hasSingle {
		single, err := source.Single.toProtoWithRawKeyEncoder(encodeRawKey)
		if err != nil {
			return nil, err
		}
		return &protobuf.SignKeySource{Source: &protobuf.SignKeySource_Single{Single: single}}, nil
	}

	keys := make([]*protobuf.KeySource, len(source.ComponentKeys))
	for index, component := range source.ComponentKeys {
		key, err := component.toProtoWithRawKeyEncoder(encodeRawKey)
		if err != nil {
			return nil, err
		}
		keys[index] = key
	}

	return &protobuf.SignKeySource{Source: &protobuf.SignKeySource_ComponentKeys{
		ComponentKeys: &protobuf.ComponentKeys{Keys: keys},
	}}, nil
}

func (format *SignatureFormat) toProto() protobuf.SignatureFormat {
	if format == nil {
		return protobuf.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED
	}
	value := protobuf.SignatureFormat(*format)
	return value
}
