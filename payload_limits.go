package cryptobrokerclientgo

import (
	"errors"
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// ErrPayloadLimitExceeded indicates that a request field exceeds its protobuf-defined limit.
var ErrPayloadLimitExceeded = errors.New("payload limit exceeded")

func checkPayloadLimit(field string, valueLen int, limit protobuf.PayloadLimits) error {
	if valueLen > int(limit) {
		return fmt.Errorf("%w: %s exceeds maximum of %d bytes", ErrPayloadLimitExceeded, field, limit)
	}

	return nil
}

func validateProfilePayload(profile string) error {
	return checkPayloadLimit("profile", len(profile), protobuf.PayloadLimits_PAYLOAD_LIMITS_PROFILE_MAX_LEN)
}

func validateMetadataPayload(metadata *Metadata) error {
	if metadata == nil {
		return nil
	}
	if err := checkPayloadLimit("metadata.id", len(metadata.Id), protobuf.PayloadLimits_PAYLOAD_LIMITS_METADATA_ID_MAX_LEN); err != nil {
		return err
	}
	if metadata.TraceContext == nil {
		return nil
	}

	fields := []struct {
		name  string
		value string
		limit protobuf.PayloadLimits
	}{
		{"metadata.traceContext.traceId", metadata.TraceContext.TraceId, protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_ID_MAX_LEN},
		{"metadata.traceContext.spanId", metadata.TraceContext.SpanId, protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_SPAN_ID_MAX_LEN},
		{"metadata.traceContext.traceFlags", metadata.TraceContext.TraceFlags, protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_FLAGS_MAX_LEN},
		{"metadata.traceContext.traceState", metadata.TraceContext.TraceState, protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_STATE_MAX_LEN},
		{"metadata.traceContext.correlationId", metadata.TraceContext.CorrelationId, protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_CORRELATION_ID_MAX_LEN},
	}
	for _, field := range fields {
		if err := checkPayloadLimit(field.name, len(field.value), field.limit); err != nil {
			return err
		}
	}

	return nil
}

func validateHashDataPayload(payload HashDataPayload) error {
	if err := validateProfilePayload(payload.Profile); err != nil {
		return err
	}
	if err := checkPayloadLimit("input", len(payload.Input), protobuf.PayloadLimits_PAYLOAD_LIMITS_HASH_DATA_INPUT_MAX_LEN); err != nil {
		return err
	}

	return validateMetadataPayload(payload.Metadata)
}

func validateSignCertificatePayload(payload SignCertificatePayload) error {
	if err := validateProfilePayload(payload.Profile); err != nil {
		return err
	}
	fields := []struct {
		name  string
		value int
		limit protobuf.PayloadLimits
	}{
		{"csr", len(payload.CSR), protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CSR_MAX_LEN},
		{"caPrivateKey", len(payload.CAPrivateKey), protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_PRIVATE_KEY_MAX_LEN},
		{"caCert", len(payload.CACert), protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_CERT_MAX_LEN},
	}
	for _, field := range fields {
		if err := checkPayloadLimit(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	if payload.Subject != nil {
		if err := checkPayloadLimit("subject", len(*payload.Subject), protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_SUBJECT_MAX_LEN); err != nil {
			return err
		}
	}
	if err := checkPayloadLimit("crlDistributionPoints", len(payload.CrlDistributionPoints), protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINTS_MAX); err != nil {
		return err
	}
	for index, point := range payload.CrlDistributionPoints {
		if err := checkPayloadLimit(fmt.Sprintf("crlDistributionPoints[%d]", index), len(point), protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINT_MAX_LEN); err != nil {
			return err
		}
	}

	return validateMetadataPayload(payload.Metadata)
}

func validateKeySourcePayload(source KeySource) error {
	if err := checkPayloadLimit("keySource.keyId", len(source.KeyID), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_KEYSOURCE_KEY_ID_MAX_LEN); err != nil {
		return err
	}

	return checkPayloadLimit("keySource.rawKey", len(source.RawKey), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_KEYSOURCE_KEY_RAW_MAX_LEN)
}

func validateEncryptDataPayload(payload EncryptDataPayload) error {
	if err := validateProfilePayload(payload.Profile); err != nil {
		return err
	}
	if err := validateKeySourcePayload(payload.KeySource); err != nil {
		return err
	}
	if err := checkPayloadLimit("plaintext", len(payload.Plaintext), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_DATA_MAX_LEN); err != nil {
		return err
	}
	if err := checkPayloadLimit("encryptMetadata.nonce", len(payload.Nonce), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_NONCE_MAX_LEN); err != nil {
		return err
	}
	if err := checkPayloadLimit("encryptMetadata.aad", len(payload.AAD), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_AAD_MAX_LEN); err != nil {
		return err
	}

	return validateMetadataPayload(payload.Metadata)
}

func validateDecryptDataPayload(payload DecryptDataPayload) error {
	if err := validateProfilePayload(payload.Profile); err != nil {
		return err
	}
	if err := validateKeySourcePayload(payload.KeySource); err != nil {
		return err
	}
	if err := checkPayloadLimit("ciphertext", len(payload.Ciphertext), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_DATA_MAX_LEN); err != nil {
		return err
	}
	if err := checkPayloadLimit("decryptMetadata.nonce", len(payload.Nonce), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_NONCE_MAX_LEN); err != nil {
		return err
	}
	if err := checkPayloadLimit("decryptMetadata.aad", len(payload.AAD), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_AAD_MAX_LEN); err != nil {
		return err
	}
	if err := checkPayloadLimit("decryptMetadata.tag", len(payload.Tag), protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_TAG_MAX_LEN); err != nil {
		return err
	}

	return validateMetadataPayload(payload.Metadata)
}

func validateSignDataPayload(payload SignDataPayload) error {
	if err := validateProfilePayload(payload.Profile); err != nil {
		return err
	}

	return validateMetadataPayload(payload.Metadata)
}

func validateVerifyDataPayload(payload VerifyDataPayload) error {
	if err := validateProfilePayload(payload.Profile); err != nil {
		return err
	}

	return validateMetadataPayload(payload.Metadata)
}
