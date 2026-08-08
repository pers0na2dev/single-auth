// Package conformancetest provides test-only helpers for emitting exact
// the reference implementation conformance evidence into a `go test -json` event stream.
package conformancetest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const evidenceMarker = "single-auth evidence: "

const (
	TransportNetHTTP  = "net/http"
	TransportFastHTTP = "fasthttp"
	TransportFiber    = "fiber"
)

// Dimension identifies the transport and real storage backend exercised by a
// single leaf test. Leave either field empty when it does not apply.
type Dimension struct {
	Transport      string
	StorageBackend string
}

type record struct {
	UpstreamTestID string `json:"upstreamTestId"`
	Transport      string `json:"transport,omitempty"`
	StorageBackend string `json:"storageBackend,omitempty"`
}

// Log emits one machine-readable evidence record. Call it only after all
// assertions for that upstream leaf and execution dimension have passed.
func Log(t testing.TB, upstreamTestID string, dimension Dimension) {
	t.Helper()
	encoded, err := encode(upstreamTestID, dimension)
	if err != nil {
		t.Fatalf("invalid conformance evidence: %v", err)
	}
	t.Logf("%s%s", evidenceMarker, encoded)
}

func encode(upstreamTestID string, dimension Dimension) ([]byte, error) {
	if strings.TrimSpace(upstreamTestID) == "" {
		return nil, fmt.Errorf("upstream test ID is empty")
	}
	if upstreamTestID != strings.TrimSpace(upstreamTestID) {
		return nil, fmt.Errorf("upstream test ID has surrounding whitespace")
	}
	if dimension.Transport != strings.TrimSpace(dimension.Transport) {
		return nil, fmt.Errorf("transport has surrounding whitespace")
	}
	switch dimension.Transport {
	case "", TransportNetHTTP, TransportFastHTTP, TransportFiber:
	default:
		return nil, fmt.Errorf("unsupported transport %q", dimension.Transport)
	}
	if dimension.StorageBackend != strings.TrimSpace(dimension.StorageBackend) {
		return nil, fmt.Errorf("storage backend has surrounding whitespace")
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record{
		UpstreamTestID: upstreamTestID,
		Transport:      dimension.Transport,
		StorageBackend: dimension.StorageBackend,
	}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}
