package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedFacadeIsCurrent(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..", "..")
	generated, err := generate(options{
		coreDir:     filepath.Join(repositoryRoot, "core"),
		packageName: "singleauth",
		coreImport:  "github.com/pers0na2dev/single-auth/core",
	})
	if err != nil {
		t.Fatalf("generate facade: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(repositoryRoot, "facade_gen.go"))
	if err != nil {
		t.Fatalf("read generated facade: %v", err)
	}
	if !bytes.Equal(generated, want) {
		t.Fatal("facade_gen.go is stale; run go generate .")
	}
}
