package openapi

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// core_catalog.json is generated from the frozen 1.6.26 snapshot and contains
// endpoint annotations only. Generator still enumerates the live registry and
// constructs models, servers, plugin paths, and user-input fields at runtime.
//
//go:embed core_catalog.json
var coreCatalogJSON []byte

type coreCatalog struct {
	ReferenceVersion string              `json:"referenceVersion"`
	SnapshotSHA256   string              `json:"snapshotSHA256"`
	Paths            map[string]PathItem `json:"paths"`
}

func loadCoreCatalog() (coreCatalog, error) {
	var catalog coreCatalog
	if err := json.Unmarshal(coreCatalogJSON, &catalog); err != nil {
		return coreCatalog{}, fmt.Errorf("openapi: decode frozen core catalog: %w", err)
	}
	if catalog.ReferenceVersion != Version || len(catalog.Paths) == 0 {
		return coreCatalog{}, fmt.Errorf("openapi: invalid frozen core catalog version %q", catalog.ReferenceVersion)
	}
	return catalog, nil
}

func cloneJSON[T any](value T) T {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var clone T
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return value
	}
	return clone
}
