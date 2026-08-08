package main

import (
	"path/filepath"
	"testing"
)

func TestInferRepositoryRootFromConformanceManifest(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "conformance", "capability-map.json")
	actual, err := inferRepositoryRoot(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if actual != root {
		t.Fatalf("inferRepositoryRoot()=%q, want %q", actual, root)
	}
}
