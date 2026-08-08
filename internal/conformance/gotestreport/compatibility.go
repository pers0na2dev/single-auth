package gotestreport

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type compatibilityMap struct {
	Entries []compatibilityEntry `json:"entries"`
}

type compatibilityUpdateFragment struct {
	ExpectedCount int                  `json:"expectedCount"`
	Updates       []compatibilityEntry `json:"updates"`
}

type compatibilityEntry struct {
	UpstreamTestID  string   `json:"upstreamTestId"`
	Status          string   `json:"status"`
	Transports      []string `json:"transports"`
	StorageBackends []string `json:"storageBackends"`
	Implementation  struct {
		Kind string `json:"kind"`
	} `json:"implementation"`
}

type exactOwner struct {
	test   string
	status string
}

// ComparePassingGo attaches a comparison against every compatibility-map entry that
// is both status=passing and implementation.kind=go-test. Pending Go tests may
// appear as UnexpectedIDs; they do not satisfy accepted compatibility prematurely.
func ComparePassingGo(report *Report, reader io.Reader) error {
	return comparePassingGo(report, reader, true)
}

// ComparePassingGoWithCandidates also validates explicit pending update
// fragments without mutating the accepted compatibility map. This lets an audit prove
// every candidate execution dimension before the fragment gains accepted=true.
func ComparePassingGoWithCandidates(report *Report, reader io.Reader, candidateReaders ...io.Reader) error {
	return comparePassingGo(report, reader, true, candidateReaders...)
}

// CompareCandidateFragments validates only the explicitly supplied pending
// fragments while still using the base map to reject unknown or already
// accepted IDs. It is intended for focused pre-acceptance package runs.
func CompareCandidateFragments(report *Report, reader io.Reader, candidateReaders ...io.Reader) error {
	if len(candidateReaders) == 0 {
		return fmt.Errorf("candidate comparison requires at least one fragment")
	}
	return comparePassingGo(report, reader, false, candidateReaders...)
}

func comparePassingGo(report *Report, reader io.Reader, includeAccepted bool, candidateReaders ...io.Reader) error {
	if report == nil {
		return fmt.Errorf("go test report is nil")
	}
	var manifest compatibilityMap
	if err := decodeSingleJSON(reader, &manifest); err != nil {
		return fmt.Errorf("decode compatibility map: %w", err)
	}

	allEntries := map[string]compatibilityEntry{}
	expected := map[string]compatibilityEntry{}
	for index, entry := range manifest.Entries {
		if entry.UpstreamTestID == "" {
			return fmt.Errorf("compatibility map entry %d has no upstreamTestId", index)
		}
		if _, exists := allEntries[entry.UpstreamTestID]; exists {
			return fmt.Errorf("duplicate compatibility-map upstreamTestId %q", entry.UpstreamTestID)
		}
		allEntries[entry.UpstreamTestID] = entry
		if includeAccepted && entry.Status == "passing" && entry.Implementation.Kind == "go-test" {
			expected[entry.UpstreamTestID] = entry
		}
	}
	acceptedCount := len(expected)
	candidateCount := 0
	for index, candidateReader := range candidateReaders {
		var fragment compatibilityUpdateFragment
		if err := decodeSingleJSON(candidateReader, &fragment); err != nil {
			return fmt.Errorf("decode candidate fragment %d: %w", index+1, err)
		}
		if fragment.ExpectedCount <= 0 || fragment.ExpectedCount != len(fragment.Updates) {
			return fmt.Errorf(
				"candidate fragment %d expectedCount=%d updates=%d",
				index+1, fragment.ExpectedCount, len(fragment.Updates),
			)
		}
		for updateIndex, entry := range fragment.Updates {
			if entry.UpstreamTestID == "" {
				return fmt.Errorf("candidate fragment %d update %d has no upstreamTestId", index+1, updateIndex)
			}
			base, exists := allEntries[entry.UpstreamTestID]
			if !exists {
				return fmt.Errorf("candidate fragment %d references unknown upstreamTestId %q", index+1, entry.UpstreamTestID)
			}
			if _, exists := expected[entry.UpstreamTestID]; exists {
				return fmt.Errorf("candidate fragment %d duplicates accepted or candidate upstreamTestId %q", index+1, entry.UpstreamTestID)
			}
			if base.Status == "passing" {
				return fmt.Errorf("candidate fragment %d targets already-passing upstreamTestId %q", index+1, entry.UpstreamTestID)
			}
			if entry.Status != "passing" || entry.Implementation.Kind != "go-test" {
				return fmt.Errorf("candidate fragment %d update %q is not a passing go-test", index+1, entry.UpstreamTestID)
			}
			expected[entry.UpstreamTestID] = entry
			candidateCount++
		}
	}

	owners := map[string][]exactOwner{}
	ownerKeysByID := map[string][]string{}
	observedIDs := map[string]struct{}{}
	for _, test := range report.Tests {
		name := test.Package + "::" + test.Test
		for _, evidence := range test.Evidence {
			observedIDs[evidence.UpstreamTestID] = struct{}{}
			if test.HasChildren {
				continue
			}
			key := evidenceKey(evidence)
			if _, exists := owners[key]; !exists {
				ownerKeysByID[evidence.UpstreamTestID] = append(ownerKeysByID[evidence.UpstreamTestID], key)
			}
			owners[key] = append(owners[key], exactOwner{test: name, status: test.Status})
		}
	}

	result := &CompatibilityResult{
		ExpectedAcceptedGoIDs: acceptedCount,
		CandidateGoIDs:        candidateCount,
		ExpectedPassingGoIDs:  len(expected),
	}
	for _, test := range report.Tests {
		if !test.HasChildren {
			continue
		}
		name := test.Package + "::" + test.Test
		for _, evidence := range test.Evidence {
			result.NonLeafEvidence = append(result.NonLeafEvidence, EvidenceLocation{
				ID: evidence.UpstreamTestID, Transport: evidence.Transport,
				StorageBackend: evidence.StorageBackend, Test: name,
			})
		}
	}
	missingIDs := map[string]struct{}{}
	nonPassingIDs := map[string]struct{}{}
	for id, entry := range expected {
		complete := true
		expectedDimensions := map[string]struct{}{}
		dimensions := expectedEvidence(entry)
		result.ExpectedDimensions += len(dimensions)
		for _, dimension := range dimensions {
			key := evidenceKey(dimension)
			expectedDimensions[key] = struct{}{}
			dimensionOwners := owners[key]
			switch {
			case len(dimensionOwners) == 0:
				complete = false
				missingIDs[id] = struct{}{}
				result.MissingDimensions = append(result.MissingDimensions, evidenceDimension(dimension))
			case len(dimensionOwners) > 1:
				complete = false
			case dimensionOwners[0].status != "pass":
				complete = false
				nonPassingIDs[id] = struct{}{}
			default:
				result.ObservedPassingDimensions++
			}
		}
		for _, key := range ownerKeysByID[id] {
			dimension := evidenceFromKey(key)
			if _, exists := expectedDimensions[key]; !exists {
				complete = false
				result.UnexpectedDimensions = append(result.UnexpectedDimensions, evidenceDimension(dimension))
			}
		}
		if complete {
			result.ObservedPassingIDs++
		}
	}
	for id := range observedIDs {
		if _, exists := expected[id]; !exists {
			result.UnexpectedIDs = append(result.UnexpectedIDs, id)
		}
	}
	for key, dimensionOwners := range owners {
		if len(dimensionOwners) > 1 {
			result.Duplicates = append(result.Duplicates, duplicate(evidenceFromKey(key), dimensionOwners))
		}
	}

	result.MissingIDs = sortedSet(missingIDs)
	result.NonPassingIDs = sortedSet(nonPassingIDs)
	sort.Strings(result.UnexpectedIDs)
	sortEvidenceDimensions(result.MissingDimensions)
	sortEvidenceDimensions(result.UnexpectedDimensions)
	sort.Slice(result.NonLeafEvidence, func(i, j int) bool {
		left := result.NonLeafEvidence[i]
		right := result.NonLeafEvidence[j]
		return left.ID+"\x00"+left.Transport+"\x00"+left.StorageBackend+"\x00"+left.Test <
			right.ID+"\x00"+right.Transport+"\x00"+right.StorageBackend+"\x00"+right.Test
	})
	sort.Slice(result.Duplicates, func(i, j int) bool {
		left := result.Duplicates[i]
		right := result.Duplicates[j]
		return left.ID+"\x00"+left.Transport+"\x00"+left.StorageBackend <
			right.ID+"\x00"+right.Transport+"\x00"+right.StorageBackend
	})
	if result.ExpectedPassingGoIDs > 0 {
		result.CoveragePercent = float64(result.ObservedPassingIDs) * 100 /
			float64(result.ExpectedPassingGoIDs)
	}
	if result.ExpectedDimensions > 0 {
		result.DimensionCoveragePercent = float64(result.ObservedPassingDimensions) * 100 /
			float64(result.ExpectedDimensions)
	}
	report.Compatibility = result
	return nil
}

func decodeSingleJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func duplicate(evidence Evidence, owners []exactOwner) DuplicateExactID {
	tests := make([]string, 0, len(owners))
	for _, current := range owners {
		tests = append(tests, current.test)
	}
	sort.Strings(tests)
	return DuplicateExactID{
		ID: evidence.UpstreamTestID, Transport: evidence.Transport,
		StorageBackend: evidence.StorageBackend, Tests: tests,
	}
}

func expectedEvidence(entry compatibilityEntry) []Evidence {
	transports := entry.Transports
	if len(transports) == 0 {
		transports = []string{""}
	}
	backends := entry.StorageBackends
	if len(backends) == 0 {
		backends = []string{""}
	}
	result := make([]Evidence, 0, len(transports)*len(backends))
	seen := map[string]struct{}{}
	for _, transport := range transports {
		for _, backend := range backends {
			evidence := Evidence{
				UpstreamTestID: entry.UpstreamTestID,
				Transport:      transport,
				StorageBackend: backend,
			}
			key := evidenceKey(evidence)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, evidence)
		}
	}
	return result
}

func evidenceFromKey(key string) Evidence {
	parts := strings.SplitN(key, "\x00", 3)
	return Evidence{
		UpstreamTestID: parts[0],
		Transport:      parts[1],
		StorageBackend: parts[2],
	}
}

func evidenceDimension(evidence Evidence) EvidenceDimension {
	return EvidenceDimension{
		ID: evidence.UpstreamTestID, Transport: evidence.Transport,
		StorageBackend: evidence.StorageBackend,
	}
}

func sortEvidenceDimensions(values []EvidenceDimension) {
	sort.Slice(values, func(i, j int) bool {
		left := values[i]
		right := values[j]
		return left.ID+"\x00"+left.Transport+"\x00"+left.StorageBackend <
			right.ID+"\x00"+right.Transport+"\x00"+right.StorageBackend
	})
}

// PassingMapSatisfied reports whether every accepted Go ID was observed once
// in a passing test. Unexpected IDs are allowed so pending work can run without
// being counted as accepted.
func PassingMapSatisfied(result *CompatibilityResult) bool {
	return result != nil &&
		len(result.MissingIDs) == 0 &&
		len(result.NonPassingIDs) == 0 &&
		len(result.UnexpectedDimensions) == 0 &&
		len(result.NonLeafEvidence) == 0 &&
		len(result.Duplicates) == 0
}
