package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type capabilityMap struct {
	SchemaVersion int          `json:"schemaVersion"`
	Module        string       `json:"module"`
	Capabilities  []capability `json:"capabilities"`
}

type capability struct {
	ID                  string               `json:"id"`
	Category            string               `json:"category"`
	Title               string               `json:"title"`
	Status              string               `json:"status"`
	ObservableContracts []observableContract `json:"observableContracts"`
	Dimensions          dimensions           `json:"dimensions"`
}

type observableContract struct {
	ID         string   `json:"id"`
	Assertions []string `json:"assertions"`
}

type dimensions struct {
	Transports      []string `json:"transports"`
	StorageBackends []string `json:"storageBackends"`
	TestKinds       []string `json:"testKinds"`
}

type categorySummary struct {
	ID      string
	Total   int
	Passing int
	Partial int
}

func main() {
	checkOnly := flag.Bool("check", false, "verify that the checked-in capability reference is current")
	flag.Parse()

	root, err := os.Getwd()
	check(err)
	data, err := os.ReadFile(filepath.Join(root, "conformance", "capability-map.json"))
	check(err)
	page, count, err := renderCapabilities(data)
	check(err)

	path := filepath.Join(root, "docs", "content", "docs", "reference", "capabilities.md")
	if *checkOnly {
		actual, readErr := os.ReadFile(path)
		check(readErr)
		if string(actual) != page {
			panic("capability reference is stale; run go run ./docs/scripts/capabilities")
		}
		fmt.Printf("verified %d capability groups\n", count)
		return
	}
	check(os.WriteFile(path, []byte(page), 0o644))
	fmt.Printf("generated %d capability groups\n", count)
}

func renderCapabilities(data []byte) (string, int, error) {
	var manifest capabilityMap
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", 0, fmt.Errorf("decode capability map: %w", err)
	}
	if manifest.Module == "" {
		return "", 0, fmt.Errorf("capability map module is required")
	}
	if len(manifest.Capabilities) == 0 {
		return "", 0, fmt.Errorf("capability map contains no capabilities")
	}

	seenIDs := make(map[string]struct{}, len(manifest.Capabilities))
	categoryOrder := make([]string, 0)
	summaries := make(map[string]*categorySummary)
	totalPassing := 0
	totalPartial := 0
	for _, item := range manifest.Capabilities {
		if item.ID == "" || item.Category == "" || item.Title == "" {
			return "", 0, fmt.Errorf("capability id, category, and title are required")
		}
		if _, exists := seenIDs[item.ID]; exists {
			return "", 0, fmt.Errorf("duplicate capability id %q", item.ID)
		}
		seenIDs[item.ID] = struct{}{}
		summary, exists := summaries[item.Category]
		if !exists {
			summary = &categorySummary{ID: item.Category}
			summaries[item.Category] = summary
			categoryOrder = append(categoryOrder, item.Category)
		}
		summary.Total++
		switch item.Status {
		case "passing":
			summary.Passing++
			totalPassing++
		case "partial":
			summary.Partial++
			totalPartial++
		default:
			return "", 0, fmt.Errorf("capability %q has unsupported status %q", item.ID, item.Status)
		}
	}

	var output strings.Builder
	output.WriteString(`---
title: "Capability matrix"
description: "Generated observable-contract status for every native Go server, transport, storage, protocol, and plugin capability."
---

This page is generated from ` + "`conformance/capability-map.json`" + `. It measures unique observable Go capabilities, not duplicated upstream test leaves.

The current map contains **`)
	output.WriteString(fmt.Sprintf("%d capability groups: %d passing and %d partial", len(manifest.Capabilities), totalPassing, totalPartial))
	output.WriteString(`**.

## How to read status

- **Passing** means the capability map records production Go implementation and the applicable conformance evidence for its declared dimensions.
- **Partial** means at least one listed observable behavior remains incomplete. Read the capability and its linked narrative page before relying on it.
- Empty transport or storage dimensions mean the capability is a transport-neutral primitive or does not directly own persistence; they do not mean the package is unavailable.

Run ` + "`go run ./internal/conformance/cmd/capability-report`" + ` from the repository root to validate the map's evidence paths. The explicit upstream audit mode additionally reads the preserved reference tree; ordinary Go tests and documentation builds do not.

## Summary

| Category | Total | Passing | Partial |
| --- | ---: | ---: | ---: |
`)
	for _, category := range categoryOrder {
		summary := summaries[category]
		output.WriteString(fmt.Sprintf(
			"| %s | %d | %d | %d |\n",
			categoryTitle(category), summary.Total, summary.Passing, summary.Partial,
		))
	}

	for _, category := range categoryOrder {
		output.WriteString("\n## " + categoryTitle(category) + "\n")
		for _, item := range manifest.Capabilities {
			if item.Category != category {
				continue
			}
			output.WriteString("\n### `" + item.ID + "`\n\n")
			output.WriteString("**" + item.Title + "**\n\n")
			output.WriteString("Status: **" + strings.ToUpper(item.Status[:1]) + item.Status[1:] + "**.\n\n")
			output.WriteString("Coverage dimensions:\n\n")
			output.WriteString("- Transports: " + dimensionValue(item.Dimensions.Transports) + "\n")
			output.WriteString("- Storage backends: " + dimensionValue(item.Dimensions.StorageBackends) + "\n")
			output.WriteString("- Evidence kinds: " + dimensionValue(item.Dimensions.TestKinds) + "\n")

			output.WriteString("\nObservable contracts:\n")
			for _, contract := range item.ObservableContracts {
				output.WriteString("\n- `" + contract.ID + "`\n")
				for _, assertion := range contract.Assertions {
					output.WriteString("  - " + strings.TrimSpace(assertion) + "\n")
				}
			}
		}
	}

	output.WriteString(`
## Scope boundary

The matrix intentionally excludes the native Go HTTP client, the deferred CLI, billing/payment plugins, JavaScript-only runtimes and ORMs, and build-tool compatibility. The separately tested browser, React, Next.js, Vue, and Solid package is shipped but does not increase the native Go denominator.

Update the manifest only after applicable production behavior and evidence pass. Then regenerate this page with ` + "`go run ./docs/scripts/capabilities`" + ` and verify it with ` + "`go run ./docs/scripts/capabilities -check`" + `.
`)
	return output.String(), len(manifest.Capabilities), nil
}

func categoryTitle(category string) string {
	titles := map[string]string{
		"core-http":         "Core HTTP",
		"transports":        "Transports",
		"native-storage":    "Native storage",
		"protocols-plugins": "Protocols and plugins",
	}
	if title := titles[category]; title != "" {
		return title
	}
	parts := strings.Fields(strings.NewReplacer("-", " ", "_", " ").Replace(category))
	if len(parts) == 0 {
		return category
	}
	for index := range parts {
		parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
	}
	return strings.Join(parts, " ")
}

func dimensionValue(values []string) string {
	if len(values) == 0 {
		return "transport-neutral or not applicable"
	}
	copyOfValues := append([]string(nil), values...)
	sort.Strings(copyOfValues)
	for index := range copyOfValues {
		copyOfValues[index] = "`" + copyOfValues[index] + "`"
	}
	return strings.Join(copyOfValues, ", ")
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
