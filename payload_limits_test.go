package cryptobrokerclientgo

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

func TestValidatePayloadLimits(t *testing.T) {
	tests := []struct {
		name     string
		validate func() error
	}{
		{
			name: "profile",
			validate: func() error {
				return validateHashDataPayload(HashDataPayload{Profile: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_PROFILE_MAX_LEN)+1)})
			},
		},
		{
			name: "metadata ID",
			validate: func() error {
				return validateMetadataPayload(&Metadata{Id: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_METADATA_ID_MAX_LEN)+1)})
			},
		},
		{
			name: "trace ID",
			validate: func() error {
				return validateMetadataPayload(&Metadata{TraceContext: &TraceContext{
					TraceId: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_ID_MAX_LEN)+1),
				}})
			},
		},
		{
			name: "span ID",
			validate: func() error {
				return validateMetadataPayload(&Metadata{TraceContext: &TraceContext{
					SpanId: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_SPAN_ID_MAX_LEN)+1),
				}})
			},
		},
		{
			name: "trace flags",
			validate: func() error {
				return validateMetadataPayload(&Metadata{TraceContext: &TraceContext{
					TraceFlags: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_FLAGS_MAX_LEN)+1),
				}})
			},
		},
		{
			name: "trace state",
			validate: func() error {
				return validateMetadataPayload(&Metadata{TraceContext: &TraceContext{
					TraceState: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_STATE_MAX_LEN)+1),
				}})
			},
		},
		{
			name: "correlation ID",
			validate: func() error {
				return validateMetadataPayload(&Metadata{TraceContext: &TraceContext{
					CorrelationId: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_CORRELATION_ID_MAX_LEN)+1),
				}})
			},
		},
		{
			name: "hash input",
			validate: func() error {
				return validateHashDataPayload(HashDataPayload{Input: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_HASH_DATA_INPUT_MAX_LEN)+1)})
			},
		},
		{
			name: "certificate signing request",
			validate: func() error {
				return validateSignCertificatePayload(SignCertificatePayload{CSR: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CSR_MAX_LEN)+1)})
			},
		},
		{
			name: "certificate authority private key",
			validate: func() error {
				return validateSignCertificatePayload(SignCertificatePayload{CAPrivateKey: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_PRIVATE_KEY_MAX_LEN)+1)})
			},
		},
		{
			name: "certificate authority certificate",
			validate: func() error {
				return validateSignCertificatePayload(SignCertificatePayload{CACert: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_CERT_MAX_LEN)+1)})
			},
		},
		{
			name: "certificate subject",
			validate: func() error {
				subject := strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_SUBJECT_MAX_LEN)+1)
				return validateSignCertificatePayload(SignCertificatePayload{Subject: &subject})
			},
		},
		{
			name: "certificate distribution point count",
			validate: func() error {
				return validateSignCertificatePayload(SignCertificatePayload{CrlDistributionPoints: make([]string, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINTS_MAX)+1)})
			},
		},
		{
			name: "certificate distribution point length",
			validate: func() error {
				return validateSignCertificatePayload(SignCertificatePayload{CrlDistributionPoints: []string{strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINT_MAX_LEN)+1)}})
			},
		},
		{
			name: "encryption key ID",
			validate: func() error {
				return validateEncryptDataPayload(EncryptDataPayload{KeySource: KeySource{KeyID: strings.Repeat("a", int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_KEYSOURCE_KEY_ID_MAX_LEN)+1)}})
			},
		},
		{
			name: "encryption raw key",
			validate: func() error {
				return validateEncryptDataPayload(EncryptDataPayload{KeySource: KeySource{RawKey: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_KEYSOURCE_KEY_RAW_MAX_LEN)+1)}})
			},
		},
		{
			name: "encryption plaintext",
			validate: func() error {
				return validateEncryptDataPayload(EncryptDataPayload{Plaintext: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_DATA_MAX_LEN)+1)})
			},
		},
		{
			name: "encryption nonce",
			validate: func() error {
				return validateEncryptDataPayload(EncryptDataPayload{Nonce: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_NONCE_MAX_LEN)+1)})
			},
		},
		{
			name: "encryption AAD",
			validate: func() error {
				return validateEncryptDataPayload(EncryptDataPayload{AAD: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_AAD_MAX_LEN)+1)})
			},
		},
		{
			name: "decryption ciphertext",
			validate: func() error {
				return validateDecryptDataPayload(DecryptDataPayload{Ciphertext: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_DATA_MAX_LEN)+1)})
			},
		},
		{
			name: "decryption nonce",
			validate: func() error {
				return validateDecryptDataPayload(DecryptDataPayload{Nonce: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_NONCE_MAX_LEN)+1)})
			},
		},
		{
			name: "decryption AAD",
			validate: func() error {
				return validateDecryptDataPayload(DecryptDataPayload{AAD: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_AAD_MAX_LEN)+1)})
			},
		},
		{
			name: "decryption tag",
			validate: func() error {
				return validateDecryptDataPayload(DecryptDataPayload{Tag: make([]byte, int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_TAG_MAX_LEN)+1)})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.validate(); !errors.Is(err, ErrPayloadLimitExceeded) {
				t.Fatalf("validation error = %v, want ErrPayloadLimitExceeded", err)
			}
		})
	}
}
