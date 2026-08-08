package capability

import (
	"fmt"
	"io"
	"sort"
)

// Report is a deterministic aggregate of one validated capability map.
type Report struct {
	SchemaVersion int               `json:"schemaVersion"`
	Module        string            `json:"module"`
	Summary       StatusSummary     `json:"summary"`
	Evidence      EvidenceSummary   `json:"evidence"`
	Categories    []CategorySummary `json:"categories"`
	Exclusions    []string          `json:"exclusions"`
}

type StatusSummary struct {
	Total          int     `json:"total"`
	Passing        int     `json:"passing"`
	Partial        int     `json:"partial"`
	Missing        int     `json:"missing"`
	PassingPercent float64 `json:"passingPercent"`
}

type CategorySummary struct {
	Category Category `json:"category"`
	StatusSummary
	EvidenceSummary
}

// EvidenceSummary makes the behavioral denominator auditable independently
// from passing/partial/missing status counts.
type EvidenceSummary struct {
	ObservableContracts int `json:"observableContracts"`
	Assertions          int `json:"assertions"`
	UpstreamRefs        int `json:"upstreamRefs"`
	UpstreamCases       int `json:"upstreamCases"`
}

// BuildReport counts capabilities by category. Coverage counts only accepted
// passing groups; partial work is reported separately and never inflates it.
func BuildReport(manifest Manifest) Report {
	report := Report{SchemaVersion: SchemaVersion, Module: manifest.Module}
	byCategory := make(map[Category]int, len(categoryOrder))
	for _, category := range categoryOrder {
		report.Categories = append(report.Categories, CategorySummary{Category: category})
		byCategory[category] = len(report.Categories) - 1
	}
	for _, entry := range manifest.Capabilities {
		addStatus(&report.Summary, entry.Status)
		index := byCategory[entry.Category]
		addStatus(&report.Categories[index].StatusSummary, entry.Status)
		addEvidence(&report.Evidence, entry)
		addEvidence(&report.Categories[index].EvidenceSummary, entry)
	}
	finalizeSummary(&report.Summary)
	for index := range report.Categories {
		finalizeSummary(&report.Categories[index].StatusSummary)
	}
	for _, exclusion := range manifest.Exclusions {
		report.Exclusions = append(report.Exclusions, exclusion.ID)
	}
	sort.Strings(report.Exclusions)
	return report
}

func addEvidence(summary *EvidenceSummary, capability Capability) {
	summary.ObservableContracts += len(capability.ObservableContracts)
	for _, contract := range capability.ObservableContracts {
		summary.Assertions += len(contract.Assertions)
	}
	summary.UpstreamRefs += len(capability.UpstreamRefs)
	for _, reference := range capability.UpstreamRefs {
		summary.UpstreamCases += len(reference.Cases)
	}
}

func addStatus(summary *StatusSummary, status Status) {
	summary.Total++
	switch status {
	case StatusPassing:
		summary.Passing++
	case StatusPartial:
		summary.Partial++
	case StatusMissing:
		summary.Missing++
	}
}

func finalizeSummary(summary *StatusSummary) {
	if summary.Total == 0 {
		return
	}
	summary.PassingPercent = float64(summary.Passing) * 100 / float64(summary.Total)
}

// WriteText prints a compact human-readable category report.
func WriteText(writer io.Writer, report Report) error {
	if _, err := fmt.Fprintf(writer, "single-auth Go capabilities (schema %d)\n", report.SchemaVersion); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "category                 passing partial missing total coverage"); err != nil {
		return err
	}
	for _, category := range report.Categories {
		if _, err := fmt.Fprintf(
			writer, "%-24s %7d %7d %7d %5d %7.1f%%\n",
			category.Category, category.Passing, category.Partial,
			category.Missing, category.Total, category.PassingPercent,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(
		writer, "%-24s %7d %7d %7d %5d %7.1f%%\n",
		"overall", report.Summary.Passing, report.Summary.Partial,
		report.Summary.Missing, report.Summary.Total, report.Summary.PassingPercent,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		writer,
		"observable contracts: %d; assertions: %d; upstream refs: %d; upstream cases: %d\n",
		report.Evidence.ObservableContracts, report.Evidence.Assertions,
		report.Evidence.UpstreamRefs, report.Evidence.UpstreamCases,
	); err != nil {
		return err
	}
	_, err := fmt.Fprintf(writer, "excluded by scope: %d\n", len(report.Exclusions))
	return err
}
