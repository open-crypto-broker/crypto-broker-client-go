package cryptobrokerclientgo

import (
	"context"
	"fmt"
	"time"

	protobuf "github.com/open-crypto-broker/crypto-broker-client-go/internal/gen/cryptobroker/v1"
)

type OutputFormatSign protobuf.SignOutputFormat

const (
	OutputFormatDer OutputFormatSign = OutputFormatSign(protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_DER)
	OutputFormatPem OutputFormatSign = OutputFormatSign(protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_PEM)
)

// SignCertificatePayload defines data required to sign a certificate.
// Profile, CSR and KeySource are mandatory. CACert is required with a raw
// signing key and must be empty with a KMS key ID. Other optional fields are
// either left empty or taken from the profile.
type SignCertificatePayload struct {
	// Profile one of supported by crypto broker cryptogaphic profiles
	Profile string

	// CSR certificate signing request's raw bytes in PEM format
	CSR []byte

	// KeySource contains either a raw PEM/DER signing key or a KMS key ID.
	KeySource SignKeySource

	// CACert contains the CA certificate in PEM format when KeySource contains a raw key.
	// It must be empty when KeySource contains a KMS key ID because KMS provides the certificate.
	CACert []byte

	// (Optional) ValidNotBefore timestamp for notBefore validity field
	ValidNotBefore *time.Time

	// (Optional) ValidNotAfter timestamp for notAfter validity field
	ValidNotAfter *time.Time

	// (Optional) Subject in pkix.Name String format to override the one from the CSR
	Subject *string

	// (Optional) CRL Point Distribution URL
	CrlDistributionPoints []string

	// OutputFormatSign defines the format of the signed certificate output, either DER or PEM
	OutputFormat OutputFormatSign

	// (Optional) Metadata to track the request back
	Metadata *Metadata
}

var ErrInvalidSignOutputFormat = fmt.Errorf("invalid sign output format, must be either %v or %v", OutputFormatDer, OutputFormatPem)

// SignCertificate create certificate using crypto broker.
// As result it returns signed x509 certificate or non-nil error if any.
// Please familiarize yourself with the encoding options before using this method.
func (lib *Library) SignCertificate(ctx context.Context, payload SignCertificatePayload) (*protobuf.SignCertificateResponse, error) {
	keySource, err := payload.KeySource.toProto()
	if err != nil {
		return nil, err
	}
	err = validateSignCertificatePayload(payload)
	if err != nil {
		return nil, err
	}

	req := &protobuf.SignCertificateRequest{
		Profile:               payload.Profile,
		Csr:                   string(payload.CSR),
		CaCert:                string(payload.CACert),
		KeySource:             keySource,
		Subject:               payload.Subject,
		CrlDistributionPoints: payload.CrlDistributionPoints,
		Metadata:              newProtoMetadata(payload.Metadata),
	}

	switch payload.OutputFormat {
	case OutputFormatDer:
		req.OutputFormat = protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_DER
	case OutputFormatPem:
		req.OutputFormat = protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_PEM
	default:
		return nil, ErrInvalidSignOutputFormat
	}

	if payload.ValidNotBefore != nil {
		if payload.ValidNotBefore.IsZero() {
			return nil, fmt.Errorf("validNotBefore is zero")
		}

		req.ValidNotBefore = toPointerUint64(payload.ValidNotBefore.UTC().Unix())
	}

	if payload.ValidNotAfter != nil {
		if payload.ValidNotAfter.IsZero() {
			return nil, fmt.Errorf("validNotAfter is zero")
		}

		req.ValidNotAfter = toPointerUint64(payload.ValidNotAfter.UTC().Unix())
	}

	resp, err := lib.client.SignCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func toPointerUint64(value int64) *uint64 {
	v := uint64(value)
	return &v
}
