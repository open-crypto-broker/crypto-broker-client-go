package cryptobrokerclientgo

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewProtoMetadata(t *testing.T) {
	t.Run("creates a UUID when metadata is omitted", func(t *testing.T) {
		metadata := newProtoMetadata(nil)
		if metadata.GetId() == "" {
			t.Fatal("Metadata.Id is empty")
		}
		if _, err := uuid.Parse(metadata.GetId()); err != nil {
			t.Fatalf("Metadata.Id = %q, want UUID: %v", metadata.GetId(), err)
		}
		if metadata.GetTraceContext() != nil {
			t.Fatalf("TraceContext = %#v, want nil", metadata.GetTraceContext())
		}
	})

	t.Run("maps caller-provided metadata and trace context", func(t *testing.T) {
		metadata := newProtoMetadata(&Metadata{
			Id: "request-id",
			TraceContext: &TraceContext{
				TraceId:       "trace-id",
				SpanId:        "span-id",
				TraceFlags:    "01",
				TraceState:    "state",
				CorrelationId: "correlation-id",
			},
		})

		if metadata.GetId() != "request-id" {
			t.Fatalf("Metadata.Id = %q, want %q", metadata.GetId(), "request-id")
		}
		traceContext := metadata.GetTraceContext()
		if traceContext == nil {
			t.Fatal("TraceContext is nil")
		}
		if traceContext.GetTraceId() != "trace-id" ||
			traceContext.GetSpanId() != "span-id" ||
			traceContext.GetTraceFlags() != "01" ||
			traceContext.GetTraceState() != "state" ||
			traceContext.GetCorrelationId() != "correlation-id" {
			t.Fatalf("TraceContext = %#v, want mapped fields", traceContext)
		}
	})
}
