// Package gotestreport turns the event stream produced by `go test -json`
// into deterministic evidence that can be compared with the compatibility map.
package gotestreport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const SchemaVersion = 1

const (
	exactIDMarker  = "exact ID: "
	evidenceMarker = "single-auth evidence: "
)

// Report is a deterministic summary of one `go test -json` stream. It omits
// timestamps and elapsed durations because those values cannot be checked in
// as reproducible conformance evidence.
type Report struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Summary       Summary              `json:"summary"`
	Packages      []PackageResult      `json:"packages"`
	Tests         []TestResult         `json:"tests"`
	Compatibility *CompatibilityResult `json:"compatibility,omitempty"`
}

type Summary struct {
	Packages int `json:"packages"`
	Tests    int `json:"tests"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	ExactIDs int `json:"exactIDs"`
	Evidence int `json:"evidence"`
}

type PackageResult struct {
	Package string `json:"package"`
	Status  string `json:"status"`
}

// TestResult includes parent tests as well as leaf subtests. HasChildren makes
// that distinction explicit instead of inferring that every emitted test name
// is a leaf.
type TestResult struct {
	Package     string     `json:"package"`
	Test        string     `json:"test"`
	Status      string     `json:"status"`
	HasChildren bool       `json:"hasChildren"`
	ExactIDs    []string   `json:"exactIDs"`
	Evidence    []Evidence `json:"evidence"`
}

// Evidence identifies one execution dimension of an upstream test. HTTP
// scenarios normally emit one record per transport; storage scenarios emit
// the real backend as well. A legacy `exact ID:` log produces an evidence
// record without dimensions and is sufficient only for dimensionless entries.
type Evidence struct {
	UpstreamTestID string `json:"upstreamTestId"`
	Transport      string `json:"transport,omitempty"`
	StorageBackend string `json:"storageBackend,omitempty"`
}

type CompatibilityResult struct {
	ExpectedAcceptedGoIDs     int                 `json:"expectedAcceptedGoIDs"`
	CandidateGoIDs            int                 `json:"candidateGoIDs"`
	ExpectedPassingGoIDs      int                 `json:"expectedPassingGoIDs"`
	ObservedPassingIDs        int                 `json:"observedPassingIDs"`
	CoveragePercent           float64             `json:"coveragePercent"`
	ExpectedDimensions        int                 `json:"expectedDimensions"`
	ObservedPassingDimensions int                 `json:"observedPassingDimensions"`
	DimensionCoveragePercent  float64             `json:"dimensionCoveragePercent"`
	MissingIDs                []string            `json:"missingIDs"`
	MissingDimensions         []EvidenceDimension `json:"missingDimensions"`
	NonPassingIDs             []string            `json:"nonPassingIDs"`
	UnexpectedIDs             []string            `json:"unexpectedIDs"`
	UnexpectedDimensions      []EvidenceDimension `json:"unexpectedDimensions"`
	NonLeafEvidence           []EvidenceLocation  `json:"nonLeafEvidence"`
	Duplicates                []DuplicateExactID  `json:"duplicates"`
}

type DuplicateExactID struct {
	ID             string   `json:"id"`
	Transport      string   `json:"transport,omitempty"`
	StorageBackend string   `json:"storageBackend,omitempty"`
	Tests          []string `json:"tests"`
}

type EvidenceDimension struct {
	ID             string `json:"id"`
	Transport      string `json:"transport,omitempty"`
	StorageBackend string `json:"storageBackend,omitempty"`
}

type EvidenceLocation struct {
	ID             string `json:"id"`
	Transport      string `json:"transport,omitempty"`
	StorageBackend string `json:"storageBackend,omitempty"`
	Test           string `json:"test"`
}

type event struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

type mutableTest struct {
	status   string
	exactIDs map[string]struct{}
	evidence []Evidence
}

// Parse consumes a complete `go test -json` stream. Malformed non-empty lines
// fail the parse so truncated or mixed command output cannot silently become
// passing evidence.
func Parse(reader io.Reader) (Report, error) {
	packages := map[string]string{}
	tests := map[string]*mutableTest{}

	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var current event
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return Report{}, fmt.Errorf("decode go test event line %d: %w", line, err)
		}
		if current.Package == "" {
			return Report{}, fmt.Errorf("go test event line %d has no Package", line)
		}

		if current.Test == "" {
			if terminalAction(current.Action) {
				packages[current.Package] = current.Action
			}
			continue
		}

		key := testKey(current.Package, current.Test)
		test := tests[key]
		if test == nil {
			test = &mutableTest{
				exactIDs: map[string]struct{}{},
			}
			tests[key] = test
		}
		if terminalAction(current.Action) {
			test.status = current.Action
		}
		if evidence, ok, err := evidenceFromOutput(current.Output); err != nil {
			return Report{}, fmt.Errorf("decode conformance evidence line %d: %w", line, err)
		} else if ok {
			test.exactIDs[evidence.UpstreamTestID] = struct{}{}
			test.evidence = append(test.evidence, evidence)
		}
	}
	if err := scanner.Err(); err != nil {
		return Report{}, fmt.Errorf("read go test event stream: %w", err)
	}

	report := Report{SchemaVersion: SchemaVersion}
	for name, status := range packages {
		report.Packages = append(report.Packages, PackageResult{Package: name, Status: status})
	}
	sort.Slice(report.Packages, func(i, j int) bool {
		return report.Packages[i].Package < report.Packages[j].Package
	})

	testNames := make([]string, 0, len(tests))
	for key := range tests {
		testNames = append(testNames, key)
	}
	sort.Strings(testNames)
	for _, key := range testNames {
		packageName, testName := splitTestKey(key)
		current := tests[key]
		ids := sortedSet(current.exactIDs)
		report.Tests = append(report.Tests, TestResult{
			Package:     packageName,
			Test:        testName,
			Status:      current.status,
			HasChildren: hasChildren(tests, packageName, testName),
			ExactIDs:    ids,
			Evidence:    sortedEvidence(current.evidence),
		})
	}

	report.Summary.Packages = len(report.Packages)
	report.Summary.Tests = len(report.Tests)
	for _, test := range report.Tests {
		switch test.Status {
		case "pass":
			report.Summary.Passed++
		case "fail":
			report.Summary.Failed++
		case "skip":
			report.Summary.Skipped++
		}
		report.Summary.ExactIDs += len(test.ExactIDs)
		report.Summary.Evidence += len(test.Evidence)
	}
	return report, nil
}

func terminalAction(action string) bool {
	return action == "pass" || action == "fail" || action == "skip"
}

func evidenceFromOutput(output string) (Evidence, bool, error) {
	if index := strings.Index(output, evidenceMarker); index >= 0 {
		raw := strings.TrimSpace(output[index+len(evidenceMarker):])
		var evidence Evidence
		if err := json.Unmarshal([]byte(raw), &evidence); err != nil {
			return Evidence{}, false, err
		}
		if strings.TrimSpace(evidence.UpstreamTestID) == "" {
			return Evidence{}, false, fmt.Errorf("upstreamTestId is empty")
		}
		evidence.UpstreamTestID = strings.TrimSpace(evidence.UpstreamTestID)
		evidence.Transport = strings.TrimSpace(evidence.Transport)
		evidence.StorageBackend = strings.TrimSpace(evidence.StorageBackend)
		return evidence, true, nil
	}
	if index := strings.Index(output, exactIDMarker); index >= 0 {
		id := strings.TrimSpace(output[index+len(exactIDMarker):])
		if id != "" {
			return Evidence{UpstreamTestID: id}, true, nil
		}
	}
	return Evidence{}, false, nil
}

func testKey(packageName, testName string) string {
	return packageName + "\x00" + testName
}

func splitTestKey(key string) (string, string) {
	parts := strings.SplitN(key, "\x00", 2)
	return parts[0], parts[1]
}

func hasChildren(tests map[string]*mutableTest, packageName, testName string) bool {
	prefix := testKey(packageName, testName+"/")
	for key := range tests {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func evidenceKey(evidence Evidence) string {
	return evidence.UpstreamTestID + "\x00" + evidence.Transport + "\x00" + evidence.StorageBackend
}

func sortedEvidence(values []Evidence) []Evidence {
	result := append([]Evidence(nil), values...)
	sort.SliceStable(result, func(i, j int) bool {
		return evidenceKey(result[i]) < evidenceKey(result[j])
	})
	return result
}
