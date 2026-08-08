package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
)

func TestErrorCodeReferenceIsCompleteCurrentAndDeterministic(t *testing.T) {
	first, count := renderErrorCodes()
	second, secondCount := renderErrorCodes()
	if first != second || count != secondCount {
		t.Fatal("core error-code generation is not deterministic")
	}
	if count != len(singleauth.BaseErrorMessages) {
		t.Fatalf("documented %d core codes, want %d", count, len(singleauth.BaseErrorMessages))
	}
	for code, message := range singleauth.BaseErrorMessages {
		row := "| `" + string(code) + "` | " + escapeTable(message) + " |"
		if !strings.Contains(first, row) {
			t.Errorf("generated catalog is missing %s", code)
		}
	}

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	checkedIn, err := os.ReadFile(filepath.Join(root, "docs", "content", "docs", "reference", "error-codes.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(checkedIn) != first {
		t.Fatal("checked-in core error-code reference is stale")
	}
}
