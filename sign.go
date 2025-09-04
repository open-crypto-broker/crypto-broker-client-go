package cryptobrokerclientgo

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
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

	// Optional fileds

	// (Optional) ValidNotBeforeOffset time offset for notBefore validity field
	ValidNotBeforeOffset *string

	// (Optional) ValidNotAfterOffset time offset for notAfter validity field
	ValidNotAfterOffset *string

	// (Optional) Subject in pkix.Name String format to override the one from the CSR
	Subject *string

	// (Optional) CRL Point Distribution URL
	CrlDistributionPoint []string

	// (Optional) Metadata to track the request back
	Metadata *Metadata
}

// SignCertificate create certificate using crypto broker.
// As result it returns signed x509 certificate or non-nil error if any.
func (lib *Library) SignCertificate(ctx context.Context, payload SignCertificatePayload) (*protobuf.SignResponse, error) {

	// Create the Metadata on the fly if not provided
	if payload.Metadata == nil {
		payload.Metadata = &Metadata{
			Id:        uuid.New().String(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	req := &protobuf.SignRequest{
		Profile:               payload.Profile,
		Csr:                   string(payload.CSR),
		CaPrivateKey:          string(payload.CAPrivateKey),
		CaCert:                string(payload.CACert),
		ValidNotBeforeOffset:  payload.ValidNotBeforeOffset,
		ValidNotAfterOffset:   payload.ValidNotAfterOffset,
		Subject:               payload.Subject,
		CrlDistributionPoints: payload.CrlDistributionPoint,
		Metadata: &protobuf.Metadata{
			Id:        payload.Metadata.Id,
			CreatedAt: payload.Metadata.CreatedAt,
		},
	}

	return lib.client.Sign(ctx, req)
}
