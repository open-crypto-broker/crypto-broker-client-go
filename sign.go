package cryptobrokerclientgo

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// WithBase64Encoding returns a function that sets the output certificate encoding to base64.
// In SignCertificate method DER encoded certificate is returned as base64 encrypted string.
func WithBase64Encoding() func(opts *optionsSignCertificate) {
	return func(opts *optionsSignCertificate) {
		opts.outputCertificateEncoding = b64
	}
}

// WithPEMEncoding returns a function that sets the output certificate encoding to PEM.
func WithPEMEncoding() func(opts *optionsSignCertificate) {
	return func(opts *optionsSignCertificate) {
		opts.outputCertificateEncoding = privacyEnhancedMail
	}
}

// optionsSignCertificate represents options for signing certificate method.
type optionsSignCertificate struct {

	// outputCertificateEncoding represents encoding of the output certificate.
	outputCertificateEncoding encoding
}

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
// Please familiarize yourself with the encoding options before using this method.
func (lib *Library) SignCertificate(ctx context.Context, payload SignCertificatePayload, optsFromCaller ...func(*optionsSignCertificate)) (*protobuf.SignResponse, error) {
	options := &optionsSignCertificate{}
	defaultOptions := lib.signCertificateDefaultOptions()
	for _, opt := range defaultOptions {
		opt(options)
	}

	for _, opt := range optsFromCaller {
		opt(options)
	}

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

	resp, err := lib.client.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	switch options.outputCertificateEncoding {
	case b64:
		return resp, nil
	case privacyEnhancedMail:
		certDER, err := base64.StdEncoding.DecodeString(resp.SignedCertificate)
		if err != nil {
			return nil, err
		}

		block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
		resp.SignedCertificate = string(pem.EncodeToMemory(block))

		return resp, nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", options.outputCertificateEncoding)
	}
}

// signCertificateDefaultOptions returns default options for signing certificate method.
func (lib *Library) signCertificateDefaultOptions() []func(*optionsSignCertificate) {
	return []func(*optionsSignCertificate){WithPEMEncoding()}
}
