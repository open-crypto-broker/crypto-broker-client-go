package cryptobrokerclientgo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-client-go/internal/protobuf"
)

// BenchmarkDataPayload defines input for invoking server-side benchmarks.
// Only Metadata is accepted to keep the API consistent with other calls.
type BenchmarkDataPayload struct {
	// (Optional) Metadata to track the request back
	Metadata *Metadata
}

// BenchmarkResult mirrors the server's JSON schema for a single benchmark result.
type BenchmarkResult struct {
	Name    string `json:"name"`
	AvgTime int64  `json:"avgTime"` // nanoseconds per iteration
}

// BenchmarkResults mirrors the server's JSON schema for the full benchmark response.
type BenchmarkResults struct {
	Results []BenchmarkResult `json:"results"`
}

// BenchmarkData runs the server-side cryptographic benchmarks and returns structured results.
// For now, the server encodes results as a JSON string inside the protobuf response. This method
// decodes that JSON into typed Go structs for convenience.
func (lib *Library) BenchmarkData(ctx context.Context, payload BenchmarkDataPayload) (*BenchmarkResults, error) {
	req := &protobuf.BenchmarkRequest{
		Metadata: newProtoMetadata(payload.Metadata),
	}

	resp, err := lib.development.Benchmark(ctx, req)
	if err != nil {
		return nil, err
	}

	var results BenchmarkResults
	if err := json.Unmarshal([]byte(resp.GetBenchmarkResults()), &results); err != nil {
		return nil, fmt.Errorf("failed to decode benchmarkResults: %w", err)
	}

	return &results, nil
}
