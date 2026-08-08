package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilityReferenceIsCompleteCurrentAndDeterministic(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "conformance", "capability-map.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, count, err := renderCapabilities(data)
	if err != nil {
		t.Fatal(err)
	}
	second, secondCount, err := renderCapabilities(data)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || count != secondCount {
		t.Fatal("capability generation is not deterministic")
	}
	var manifest capabilityMap
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if count != len(manifest.Capabilities) {
		t.Fatalf("documented %d capability groups, want %d", count, len(manifest.Capabilities))
	}
	passing, partial := 0, 0
	for _, item := range manifest.Capabilities {
		switch item.Status {
		case "passing":
			passing++
		case "partial":
			partial++
		}
	}
	total := fmt.Sprintf(
		"**%d capability groups: %d passing and %d partial**",
		count, passing, partial,
	)
	if !strings.Contains(first, total) {
		t.Fatal("generated capability totals are missing or incorrect")
	}
	checkedIn, err := os.ReadFile(filepath.Join(root, "docs", "content", "docs", "reference", "capabilities.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(checkedIn) != first {
		t.Fatal("checked-in capability reference is stale")
	}
}

func TestCapabilityReferenceRejectsDuplicateIDs(t *testing.T) {
	data := []byte(`{
        "module":"example",
        "capabilities":[
            {"id":"duplicate","category":"core-http","title":"One","status":"passing"},
            {"id":"duplicate","category":"core-http","title":"Two","status":"partial"}
        ]
    }`)
	if _, _, err := renderCapabilities(data); err == nil {
		t.Fatal("expected duplicate capability id to fail")
	}
}
