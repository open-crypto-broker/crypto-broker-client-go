package cryptobrokerclientgo

import (
	"context"
	"fmt"
	"time"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

type OutputFormatSign protobuf.SignOutputFormat

const (
	OutputFormatDer OutputFormatSign = OutputFormatSign(protobuf.SignOutputFormat_DER)
	OutputFormatPem OutputFormatSign = OutputFormatSign(protobuf.SignOutputFormat_PEM)
)

// SigningOpts defines data that need to be provided in order to invoke signing of a certificate.
// The profile, CSR, Private Key and CA are mandatory, while the rest are optional. Optional fields
// will be either left empty or be taken from the Profile
type SignCertificatePayload struct {
	// Profile one of supported by crypto broker cryptogaphic profiles
	Profile string

	// CSR certificate signing request's raw bytes in PEM format
	CSR []byte

	// CAPrivateKey signing key's raw bytes in PEM format
	CAPrivateKey []byte

	// CACert CA Certificate's raw bytes in PEM format
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
	req := &protobuf.SignCertificateRequest{
		Profile:               payload.Profile,
		Csr:                   string(payload.CSR),
		CaPrivateKey:          string(payload.CAPrivateKey),
		CaCert:                string(payload.CACert),
		Subject:               payload.Subject,
		CrlDistributionPoints: payload.CrlDistributionPoints,
		Metadata:              newProtoMetadata(payload.Metadata),
	}

	switch payload.OutputFormat {
	case OutputFormatDer:
		req.OutputFormat = protobuf.SignOutputFormat_DER
	case OutputFormatPem:
		req.OutputFormat = protobuf.SignOutputFormat_PEM
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
