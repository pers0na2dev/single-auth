package conformancetest

import (
	"strings"
	"testing"
)

func TestEncodeEvidence(t *testing.T) {
	encoded, err := encode("example::<root>::works", Dimension{
		Transport:      TransportFiber,
		StorageBackend: "postgres",
	})
	if err != nil {
		t.Fatalf("encode() error = %v", err)
	}
	want := `{"upstreamTestId":"example::<root>::works","transport":"fiber","storageBackend":"postgres"}`
	if string(encoded) != want {
		t.Fatalf("encode() = %s, want %s", encoded, want)
	}
}

func TestEncodeEvidenceRejectsAmbiguousValues(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		dimension Dimension
	}{
		{name: "empty id"},
		{name: "id whitespace", id: " id"},
		{name: "unknown transport", id: "id", dimension: Dimension{Transport: "http"}},
		{name: "backend whitespace", id: "id", dimension: Dimension{StorageBackend: "sqlite "}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := encode(test.id, test.dimension)
			if err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("encode() error = %v", err)
			}
		})
	}
}
