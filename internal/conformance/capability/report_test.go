package capability

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildReportCountsEachCategoryAndStatus(t *testing.T) {
	manifest := Manifest{Module: "example", Capabilities: []Capability{
		{Category: CategoryCoreHTTP, Status: StatusPassing, ObservableContracts: []ObservableContract{{Assertions: []string{"a", "b"}}}, UpstreamRefs: []UpstreamReference{{Cases: []string{"one"}}}},
		{Category: CategoryCoreHTTP, Status: StatusPartial, ObservableContracts: []ObservableContract{{Assertions: []string{"c"}}}, UpstreamRefs: []UpstreamReference{{Cases: []string{"two", "three"}}}},
		{Category: CategoryTransports, Status: StatusPassing},
		{Category: CategoryNativeStorage, Status: StatusMissing},
		{Category: CategoryProtocolsPlugins, Status: StatusPartial},
	}, Exclusions: []Exclusion{{ID: "product-cli"}, {ID: "javascript-client"}}}

	report := BuildReport(manifest)
	if report.Summary.Total != 5 || report.Summary.Passing != 2 ||
		report.Summary.Partial != 2 || report.Summary.Missing != 1 ||
		report.Summary.PassingPercent != 40 {
		t.Fatalf("unexpected overall report: %#v", report.Summary)
	}
	if len(report.Categories) != len(Categories()) ||
		report.Categories[0].Category != CategoryCoreHTTP ||
		report.Categories[0].Total != 2 || report.Categories[0].PassingPercent != 50 {
		t.Fatalf("unexpected category report: %#v", report.Categories)
	}
	if len(report.Exclusions) != 2 || report.Exclusions[0] != "javascript-client" || report.Exclusions[1] != "product-cli" {
		t.Fatalf("exclusions are not deterministic: %#v", report.Exclusions)
	}
	if report.Evidence != (EvidenceSummary{ObservableContracts: 2, Assertions: 3, UpstreamRefs: 2, UpstreamCases: 3}) {
		t.Fatalf("unexpected evidence report: %#v", report.Evidence)
	}
	if report.Categories[0].EvidenceSummary != report.Evidence {
		t.Fatalf("unexpected category evidence: %#v", report.Categories[0].EvidenceSummary)
	}
}

func TestWriteTextPrintsCategoryPercentages(t *testing.T) {
	report := Report{
		SchemaVersion: SchemaVersion,
		Summary:       StatusSummary{Total: 2, Passing: 1, Partial: 1, PassingPercent: 50},
		Categories: []CategorySummary{{
			Category: CategoryCoreHTTP,
			StatusSummary: StatusSummary{
				Total: 2, Passing: 1, Partial: 1, PassingPercent: 50,
			},
		}},
		Evidence: EvidenceSummary{
			ObservableContracts: 2, Assertions: 4, UpstreamRefs: 2, UpstreamCases: 3,
		},
		Exclusions: []string{"product-cli"},
	}
	var output bytes.Buffer
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"single-auth Go capabilities", "core-http", "50.0%", "overall",
		"observable contracts: 2; assertions: 4; upstream refs: 2; upstream cases: 3",
		"excluded by scope: 1",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("report output missing %q:\n%s", expected, output.String())
		}
	}
}
