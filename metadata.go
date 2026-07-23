package cryptobrokerclientgo

import (
	"github.com/google/uuid"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// TraceContext carries tracing fields propagated to Crypto Broker.
type TraceContext struct {
	TraceId       string
	SpanId        string
	TraceFlags    string
	TraceState    string
	CorrelationId string
}

// Metadata identifies a client request and optionally carries trace context.
type Metadata struct {
	Id           string
	TraceContext *TraceContext
}

func newProtoMetadata(metadata *Metadata) *protobuf.Metadata {
	if metadata == nil {
		metadata = &Metadata{Id: uuid.New().String()}
	}

	var traceContext *protobuf.TraceContext
	if metadata.TraceContext != nil {
		traceContext = &protobuf.TraceContext{
			TraceId:       metadata.TraceContext.TraceId,
			SpanId:        metadata.TraceContext.SpanId,
			TraceFlags:    metadata.TraceContext.TraceFlags,
			TraceState:    metadata.TraceContext.TraceState,
			CorrelationId: metadata.TraceContext.CorrelationId,
		}
	}

	return &protobuf.Metadata{
		Id:           metadata.Id,
		TraceContext: traceContext,
	}
}
