package gotestreport

import (
	"strings"
	"testing"
)

func TestParseDeterministicGoTestEvidence(t *testing.T) {
	input := strings.Join([]string{
		`{"Action":"start","Package":"example/a"}`,
		`{"Action":"run","Package":"example/a","Test":"TestCompatibility"}`,
		`{"Action":"run","Package":"example/a","Test":"TestCompatibility/case"}`,
		`{"Action":"output","Package":"example/a","Test":"TestCompatibility/case","Output":"    compatibility_test.go:12: single-auth evidence: {\"upstreamTestId\":\"upstream/a::suite::case\",\"transport\":\"net/http\",\"storageBackend\":\"sqlite\"}\n"}`,
		`{"Action":"pass","Package":"example/a","Test":"TestCompatibility/case","Elapsed":0.01}`,
		`{"Action":"pass","Package":"example/a","Test":"TestCompatibility","Elapsed":0.02}`,
		`{"Action":"pass","Package":"example/a","Elapsed":0.02}`,
		`{"Action":"start","Package":"example/b"}`,
		`{"Action":"run","Package":"example/b","Test":"TestSkipped"}`,
		`{"Action":"skip","Package":"example/b","Test":"TestSkipped"}`,
		`{"Action":"pass","Package":"example/b"}`,
	}, "\n")

	report, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if report.SchemaVersion != SchemaVersion || report.Summary.Packages != 2 ||
		report.Summary.Tests != 3 || report.Summary.Passed != 2 ||
		report.Summary.Skipped != 1 || report.Summary.ExactIDs != 1 ||
		report.Summary.Evidence != 1 {
		t.Fatalf("unexpected report summary: %#v", report)
	}
	if !report.Tests[0].HasChildren || len(report.Tests[0].ExactIDs) != 0 {
		t.Fatalf("parent test not identified: %#v", report.Tests[0])
	}
	if report.Tests[1].HasChildren ||
		len(report.Tests[1].ExactIDs) != 1 ||
		report.Tests[1].ExactIDs[0] != "upstream/a::suite::case" ||
		len(report.Tests[1].Evidence) != 1 ||
		report.Tests[1].Evidence[0].Transport != "net/http" ||
		report.Tests[1].Evidence[0].StorageBackend != "sqlite" {
		t.Fatalf("leaf evidence mismatch: %#v", report.Tests[1])
	}
}

func TestComparePassingGo(t *testing.T) {
	report := Report{Tests: []TestResult{
		{Package: "example/a", Test: "TestCompatibility/one/http", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "net/http"}}},
		{Package: "example/a", Test: "TestCompatibility/one/fasthttp", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "fasthttp"}}},
		{Package: "example/a", Test: "TestCompatibility/two", Status: "fail", Evidence: []Evidence{{UpstreamTestID: "id-2"}}},
		{Package: "example/a", Test: "TestCompatibility/wip", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-wip"}}},
	}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-1","status":"passing","transports":["net/http","fasthttp"],"implementation":{"kind":"go-test"}},
		{"upstreamTestId":"id-2","status":"passing","implementation":{"kind":"go-test"}},
		{"upstreamTestId":"id-3","status":"passing","implementation":{"kind":"compat-js"}},
		{"upstreamTestId":"id-wip","status":"unimplemented","implementation":{"kind":"go-test"}}
	]}`
	if err := ComparePassingGo(&report, strings.NewReader(compatibility)); err != nil {
		t.Fatalf("ComparePassingGo() error = %v", err)
	}
	if report.Compatibility.ExpectedPassingGoIDs != 2 || report.Compatibility.ObservedPassingIDs != 1 ||
		len(report.Compatibility.NonPassingIDs) != 1 || report.Compatibility.NonPassingIDs[0] != "id-2" ||
		len(report.Compatibility.UnexpectedIDs) != 1 || report.Compatibility.UnexpectedIDs[0] != "id-wip" ||
		PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("unexpected compatibility comparison: %#v", report.Compatibility)
	}
}

func TestComparePassingGoRequiresEveryTransportDimension(t *testing.T) {
	report := Report{Tests: []TestResult{{
		Package: "example/a", Test: "TestCompatibility/http", Status: "pass",
		Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "net/http"}},
	}}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-1","status":"passing","transports":["net/http","fasthttp"],"implementation":{"kind":"go-test"}}
	]}`
	if err := ComparePassingGo(&report, strings.NewReader(compatibility)); err != nil {
		t.Fatalf("ComparePassingGo() error = %v", err)
	}
	if len(report.Compatibility.MissingIDs) != 1 || report.Compatibility.MissingIDs[0] != "id-1" ||
		len(report.Compatibility.MissingDimensions) != 1 ||
		report.Compatibility.MissingDimensions[0].Transport != "fasthttp" ||
		PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("missing transport was accepted: %#v", report.Compatibility)
	}
}

func TestComparePassingGoRejectsDuplicateEvidenceWithinOneTest(t *testing.T) {
	evidence := Evidence{UpstreamTestID: "id-1", Transport: "net/http"}
	report := Report{Tests: []TestResult{{
		Package: "example/a", Test: "TestCompatibility/http", Status: "pass",
		Evidence: []Evidence{evidence, evidence},
	}}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-1","status":"passing","transports":["net/http"],"implementation":{"kind":"go-test"}}
	]}`
	if err := ComparePassingGo(&report, strings.NewReader(compatibility)); err != nil {
		t.Fatalf("ComparePassingGo() error = %v", err)
	}
	if len(report.Compatibility.Duplicates) != 1 ||
		len(report.Compatibility.Duplicates[0].Tests) != 2 ||
		PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("duplicate evidence was accepted: %#v", report.Compatibility)
	}
}

func TestComparePassingGoAcceptsCompleteTransportBackendMatrix(t *testing.T) {
	report := Report{Tests: []TestResult{
		{Package: "example/a", Test: "TestCompatibility/http/sqlite", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "net/http", StorageBackend: "sqlite"}}},
		{Package: "example/a", Test: "TestCompatibility/http/redis", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "net/http", StorageBackend: "redis"}}},
		{Package: "example/a", Test: "TestCompatibility/fiber/sqlite", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "fiber", StorageBackend: "sqlite"}}},
		{Package: "example/a", Test: "TestCompatibility/fiber/redis", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-1", Transport: "fiber", StorageBackend: "redis"}}},
	}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-1","status":"passing","transports":["net/http","fiber"],"storageBackends":["sqlite","redis"],"implementation":{"kind":"go-test"}}
	]}`
	if err := ComparePassingGo(&report, strings.NewReader(compatibility)); err != nil {
		t.Fatalf("ComparePassingGo() error = %v", err)
	}
	if report.Compatibility.ObservedPassingIDs != 1 ||
		report.Compatibility.CoveragePercent != 100 ||
		report.Compatibility.ExpectedDimensions != 4 ||
		report.Compatibility.ObservedPassingDimensions != 4 ||
		report.Compatibility.DimensionCoveragePercent != 100 ||
		!PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("complete matrix was rejected: %#v", report.Compatibility)
	}
}

func TestComparePassingGoWithCandidateFragment(t *testing.T) {
	report := Report{Tests: []TestResult{
		{Package: "example/a", Test: "TestCompatibility/accepted", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-accepted"}}},
		{Package: "example/a", Test: "TestCompatibility/candidate/http", Status: "pass", Evidence: []Evidence{{UpstreamTestID: "id-candidate", Transport: "net/http", StorageBackend: "sqlite"}}},
	}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-accepted","status":"passing","implementation":{"kind":"go-test"}},
		{"upstreamTestId":"id-candidate","status":"unimplemented","implementation":{"kind":"unimplemented"}}
	]}`
	candidate := `{"expectedCount":1,"updates":[
		{"upstreamTestId":"id-candidate","status":"passing","transports":["net/http"],"storageBackends":["sqlite"],"implementation":{"kind":"go-test"}}
	]}`
	if err := ComparePassingGoWithCandidates(
		&report, strings.NewReader(compatibility), strings.NewReader(candidate),
	); err != nil {
		t.Fatalf("ComparePassingGoWithCandidates() error = %v", err)
	}
	if report.Compatibility.ExpectedAcceptedGoIDs != 1 ||
		report.Compatibility.CandidateGoIDs != 1 ||
		report.Compatibility.ExpectedPassingGoIDs != 2 ||
		report.Compatibility.ObservedPassingIDs != 2 ||
		!PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("candidate fragment was not proven: %#v", report.Compatibility)
	}
}

func TestComparePassingGoRejectsInvalidCandidateFragment(t *testing.T) {
	report := Report{}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-candidate","status":"unimplemented","implementation":{"kind":"unimplemented"}}
	]}`
	candidate := `{"expectedCount":2,"updates":[
		{"upstreamTestId":"id-candidate","status":"passing","implementation":{"kind":"go-test"}}
	]}`
	err := ComparePassingGoWithCandidates(
		&report, strings.NewReader(compatibility), strings.NewReader(candidate),
	)
	if err == nil {
		t.Fatal("ComparePassingGoWithCandidates() accepted mismatched expectedCount")
	}
}

func TestComparePassingGoRejectsTrailingCompatibilityJSON(t *testing.T) {
	report := Report{}
	err := ComparePassingGo(&report, strings.NewReader(`{"entries":[]} {}`))
	if err == nil {
		t.Fatal("ComparePassingGo() accepted multiple JSON values")
	}
}

func TestCompareCandidateFragmentsIgnoresAcceptedIDsOutsideFocusedRun(t *testing.T) {
	report := Report{Tests: []TestResult{{
		Package: "example/a", Test: "TestCompatibility/candidate", Status: "pass",
		Evidence: []Evidence{{UpstreamTestID: "id-candidate"}},
	}}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-accepted","status":"passing","implementation":{"kind":"go-test"}},
		{"upstreamTestId":"id-candidate","status":"unimplemented","implementation":{"kind":"unimplemented"}}
	]}`
	candidate := `{"expectedCount":1,"updates":[
		{"upstreamTestId":"id-candidate","status":"passing","implementation":{"kind":"go-test"}}
	]}`
	if err := CompareCandidateFragments(
		&report, strings.NewReader(compatibility), strings.NewReader(candidate),
	); err != nil {
		t.Fatalf("CompareCandidateFragments() error = %v", err)
	}
	if report.Compatibility.ExpectedAcceptedGoIDs != 0 ||
		report.Compatibility.CandidateGoIDs != 1 ||
		report.Compatibility.ObservedPassingIDs != 1 ||
		!PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("focused candidate was not proven: %#v", report.Compatibility)
	}
}

func TestComparePassingGoRejectsEvidenceOnParentTest(t *testing.T) {
	report := Report{Tests: []TestResult{{
		Package: "example/a", Test: "TestCompatibility", Status: "pass", HasChildren: true,
		Evidence: []Evidence{{UpstreamTestID: "id-1"}},
	}}}
	compatibility := `{"entries":[
		{"upstreamTestId":"id-1","status":"passing","implementation":{"kind":"go-test"}}
	]}`
	if err := ComparePassingGo(&report, strings.NewReader(compatibility)); err != nil {
		t.Fatalf("ComparePassingGo() error = %v", err)
	}
	if len(report.Compatibility.NonLeafEvidence) != 1 ||
		len(report.Compatibility.MissingIDs) != 1 ||
		PassingMapSatisfied(report.Compatibility) {
		t.Fatalf("parent evidence was accepted: %#v", report.Compatibility)
	}
}

func TestParseRejectsMalformedStructuredEvidence(t *testing.T) {
	input := `{"Action":"output","Package":"example/a","Test":"TestCompatibility","Output":"single-auth evidence: not-json\\n"}`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Parse() accepted malformed structured evidence")
	}
}

func TestParseRejectsMixedOutput(t *testing.T) {
	_, err := Parse(strings.NewReader("not json\n"))
	if err == nil {
		t.Fatal("Parse() accepted non-JSON output")
	}
}
