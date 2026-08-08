package singleauth_test

import (
	"strings"
	"testing"
)

func assertFixtureIDs(t *testing.T, ids []string) {
	t.Helper()
	if len(ids) == 0 {
		t.Fatal("fixture contains no scenarios")
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			t.Fatal("fixture contains an empty scenario ID")
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("fixture contains duplicate scenario ID %q", id)
		}
		seen[id] = struct{}{}
	}
}
