package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckedInCapabilityMapIsValidAndResolved(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..", "..")
	manifest, err := Load(filepath.Join(repositoryRoot, "conformance", "capability-map.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("checked-in capability map is invalid: %v", err)
	}
	if err := manifest.ValidateReferences(repositoryRoot); err != nil {
		t.Fatalf("checked-in capability references are invalid: %v", err)
	}
	if len(manifest.Capabilities) != 38 {
		t.Fatalf("capability groups=%d, want 38", len(manifest.Capabilities))
	}
	if len(manifest.Exclusions) != len(KnownExclusionIDs()) {
		t.Fatalf("exclusions=%d, known=%d", len(manifest.Exclusions), len(KnownExclusionIDs()))
	}
	statuses := map[Status]int{}
	for _, entry := range manifest.Capabilities {
		statuses[entry.Status]++
	}
	if statuses[StatusPassing] != 38 || statuses[StatusPartial] != 0 || statuses[StatusMissing] != 0 {
		t.Fatalf("checked-in snapshot changed without an explicit readiness update: %#v", statuses)
	}
	report := BuildReport(manifest)
	if report.Evidence.ObservableContracts < len(manifest.Capabilities) ||
		report.Evidence.Assertions < len(manifest.Capabilities)*2 ||
		report.Evidence.UpstreamRefs < len(manifest.Capabilities) ||
		report.Evidence.UpstreamCases < len(manifest.Capabilities) {
		t.Fatalf("checked-in behavioral evidence is incomplete: %#v", report.Evidence)
	}
}

func TestValidateRejectsDuplicateCapabilityIDs(t *testing.T) {
	manifest := validManifest()
	manifest.Capabilities = append(manifest.Capabilities, manifest.Capabilities[0])
	assertValidationError(t, manifest, "duplicate capability id")
}

func TestValidateRejectsInvalidStatus(t *testing.T) {
	manifest := validManifest()
	manifest.Capabilities[0].Status = Status("done")
	assertValidationError(t, manifest, "invalid status")
}

func TestValidateRejectsInvalidAndDuplicateDimensions(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].Dimensions.Transports = []string{"express"}
		assertValidationError(t, manifest, "invalid value")
	})
	t.Run("duplicate", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].Dimensions.TestKinds = []string{"unit", "unit"}
		assertValidationError(t, manifest, "duplicate value")
	})
}

func TestValidateRejectsPassingWithoutProductionOrTests(t *testing.T) {
	t.Run("production", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].ProductionRefs = nil
		assertValidationError(t, manifest, "requires productionRefs and testRefs")
	})
	t.Run("tests", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].TestRefs = nil
		assertValidationError(t, manifest, "requires productionRefs and testRefs")
	})
}

func TestValidateRejectsMissingOrMalformedBehavioralContracts(t *testing.T) {
	t.Run("missing observable contract", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].ObservableContracts = nil
		assertValidationError(t, manifest, "observable contract is required")
	})
	t.Run("invalid contract id", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].ObservableContracts[0].ID = "Not Valid"
		assertValidationError(t, manifest, "invalid id")
	})
	t.Run("missing assertions", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].ObservableContracts[0].Assertions = nil
		assertValidationError(t, manifest, "requires at least two assertions")
	})
	t.Run("short assertion", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].ObservableContracts[0].Assertions[0] = "too short"
		assertValidationError(t, manifest, "is too short")
	})
	t.Run("duplicate assertion", func(t *testing.T) {
		manifest := validManifest()
		assertion := manifest.Capabilities[0].ObservableContracts[0].Assertions[0]
		manifest.Capabilities[0].ObservableContracts[0].Assertions[1] = assertion
		assertValidationError(t, manifest, "duplicate assertion")
	})
	t.Run("missing upstream refs", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].UpstreamRefs = nil
		assertValidationError(t, manifest, "upstream reference is required")
	})
	t.Run("upstream path is not repository relative", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].UpstreamRefs[0].Path = "../reference.txt"
		assertValidationError(t, manifest, "not clean and repository-relative")
	})
	t.Run("missing upstream cases", func(t *testing.T) {
		manifest := validManifest()
		manifest.Capabilities[0].UpstreamRefs[0].Cases = nil
		assertValidationError(t, manifest, "has no cases")
	})
}

func TestValidateRejectsNonGoSupportTreeReferences(t *testing.T) {
	manifest := validManifest()
	manifest.Capabilities[0].ProductionRefs = []string{"compat/reference.go"}
	assertValidationError(t, manifest, "non-Go support tree")
}

func TestValidateRejectsUnknownExclusion(t *testing.T) {
	manifest := validManifest()
	manifest.Exclusions[0].ID = "cloud-runtime"
	assertValidationError(t, manifest, "unknown id")
}

func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"schemaVersion":1,"module":"x","capabilities":[],"exclusions":[],"unknown":true}`,
		`{"schemaVersion":1,"module":"x","capabilities":[],"exclusions":[]} {}`,
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("Decode() accepted invalid input %q", input)
		}
	}
}

func TestValidateReferencesRejectsMissingFile(t *testing.T) {
	manifest := validManifest()
	err := manifest.ValidateReferences(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "production.go") {
		t.Fatalf("ValidateReferences() error=%v, want missing production.go", err)
	}
}

func TestValidateReferencesDoesNotRequirePreservedUpstreamTree(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"production.go", "production_test.go", "decision.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validManifest().ValidateReferences(root); err != nil {
		t.Fatalf("ValidateReferences() unexpectedly required upstream source: %v", err)
	}
}

func TestValidateUpstreamReferencesChecksExactCaseSubstrings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reference.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("observable upstream case"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	for index := range manifest.Capabilities {
		manifest.Capabilities[index].UpstreamRefs = []UpstreamReference{{
			Path: "reference.txt", Cases: []string{"observable upstream case"},
		}}
	}
	if err := manifest.ValidateUpstreamReferences(root); err != nil {
		t.Fatal(err)
	}
	manifest.Capabilities[0].UpstreamRefs[0].Cases[0] = "missing case"
	err := manifest.ValidateUpstreamReferences(root)
	if err == nil || !strings.Contains(err.Error(), "does not contain case") {
		t.Fatalf("ValidateUpstreamReferences() error=%v, want missing-case error", err)
	}
}

func assertValidationError(t *testing.T, manifest Manifest, contains string) {
	t.Helper()
	err := manifest.Validate()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("Validate() error=%v, want substring %q", err, contains)
	}
}

func validManifest() Manifest {
	capability := func(id string, category Category) Capability {
		entry := Capability{
			ID: id, Category: category, Title: id, Status: StatusPassing,
			ObservableContracts: []ObservableContract{{
				ID: "observable", Assertions: []string{"The behavior is observable.", "Failures remain observable."},
			}},
			UpstreamRefs: []UpstreamReference{{
				Path: "reference.txt", Cases: []string{"observable upstream case"},
			}},
			ProductionRefs: []string{"production.go"},
			TestRefs:       []string{"production_test.go"},
			Dimensions:     Dimensions{TestKinds: []string{"unit"}},
		}
		if category == CategoryTransports {
			entry.Dimensions.Transports = []string{"net/http"}
		}
		if category == CategoryNativeStorage {
			entry.Dimensions.StorageBackends = []string{"memory"}
		}
		return entry
	}
	return Manifest{
		SchemaVersion: SchemaVersion,
		Module:        "example",
		Capabilities: []Capability{
			capability("core-http.example", CategoryCoreHTTP),
			capability("transports.example", CategoryTransports),
			capability("native-storage.example", CategoryNativeStorage),
			capability("protocols-plugins.example", CategoryProtocolsPlugins),
		},
		Exclusions: []Exclusion{{
			ID: "javascript-client", Title: "JavaScript client",
			Reason: "not part of this example", DecisionRef: "decision.md",
		}},
	}
}
