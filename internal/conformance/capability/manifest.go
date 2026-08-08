// Package capability validates and reports the native Go capability map.
//
// The capability map is intentionally independent from the historical
// one-to-one upstream test migration ledger. It tracks user-visible Go
// behavior and the dimensions in which that behavior has been exercised.
package capability

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
)

const SchemaVersion = 2

type Status string

const (
	StatusMissing Status = "missing"
	StatusPartial Status = "partial"
	StatusPassing Status = "passing"
)

type Category string

const (
	CategoryCoreHTTP         Category = "core-http"
	CategoryTransports       Category = "transports"
	CategoryNativeStorage    Category = "native-storage"
	CategoryProtocolsPlugins Category = "protocols-plugins"
)

var categoryOrder = []Category{
	CategoryCoreHTTP,
	CategoryTransports,
	CategoryNativeStorage,
	CategoryProtocolsPlugins,
}

var allowedTransports = map[string]struct{}{
	"net/http": {},
	"fasthttp": {},
	"fiber":    {},
}

var allowedStorageBackends = map[string]struct{}{
	"memory":   {},
	"sqlite":   {},
	"postgres": {},
	"mysql":    {},
	"mssql":    {},
	"mongodb":  {},
	"redis":    {},
}

var allowedTestKinds = map[string]struct{}{
	"unit":        {},
	"integration": {},
	"e2e":         {},
}

var knownExclusions = map[string]struct{}{
	"anonymous-product-telemetry":       {},
	"billing-and-payment-integrations":  {},
	"javascript-client":                 {},
	"javascript-framework-integrations": {},
	"javascript-runtime-matrix":         {},
	"native-go-client":                  {},
	"polar-oauth-provider":              {},
	"product-cli":                       {},
	"typescript-compile-contracts":      {},
	"typescript-orm-adapters":           {},
}

// Manifest is the complete native Go server capability snapshot.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Module        string       `json:"module"`
	Capabilities  []Capability `json:"capabilities"`
	Exclusions    []Exclusion  `json:"exclusions"`
}

// Capability groups one user-visible behavior rather than individual
// upstream test leaves.
type Capability struct {
	ID                  string               `json:"id"`
	Category            Category             `json:"category"`
	Title               string               `json:"title"`
	Status              Status               `json:"status"`
	Notes               string               `json:"notes,omitempty"`
	ObservableContracts []ObservableContract `json:"observableContracts"`
	UpstreamRefs        []UpstreamReference  `json:"upstreamRefs"`
	ProductionRefs      []string             `json:"productionRefs,omitempty"`
	TestRefs            []string             `json:"testRefs,omitempty"`
	Dimensions          Dimensions           `json:"dimensions,omitempty"`
}

// ObservableContract is a stable, user-visible behavior group. Assertions are
// desired wire or API observations; status says how completely the current Go
// implementation proves them.
type ObservableContract struct {
	ID         string   `json:"id"`
	Assertions []string `json:"assertions"`
}

// UpstreamReference points at the preserved reference snapshot. Path is
// relative to the snapshot root supplied to ValidateUpstreamReferences. Cases
// are exact source symbols or test-title substrings; ordinary Go tests do not
// depend on the snapshot.
type UpstreamReference struct {
	Path  string   `json:"path"`
	Cases []string `json:"cases"`
}

// Dimensions describe the native execution surface exercised by a
// capability. Values are deliberately closed so typos cannot inflate scope.
type Dimensions struct {
	Transports      []string `json:"transports,omitempty"`
	StorageBackends []string `json:"storageBackends,omitempty"`
	TestKinds       []string `json:"testKinds,omitempty"`
}

// Exclusion records a product decision that is intentionally outside the Go
// port. IDs are validated against a closed catalog.
type Exclusion struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Reason      string `json:"reason"`
	DecisionRef string `json:"decisionRef"`
}

// Load decodes one capability map. Unknown fields and trailing JSON values are
// rejected so a misspelled field cannot silently disappear from the report.
func Load(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open capability map: %w", err)
	}
	defer file.Close()
	manifest, err := Decode(file)
	if err != nil {
		return Manifest{}, fmt.Errorf("decode capability map: %w", err)
	}
	return manifest, nil
}

// Decode decodes exactly one JSON object.
func Decode(reader io.Reader) (Manifest, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, fmt.Errorf("multiple JSON values")
		}
		return Manifest{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return manifest, nil
}

// Validate checks semantic invariants without accessing the filesystem.
func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion=%d, want %d", manifest.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(manifest.Module) == "" {
		return fmt.Errorf("module is empty")
	}
	if len(manifest.Capabilities) == 0 {
		return fmt.Errorf("capabilities are empty")
	}

	seenIDs := make(map[string]struct{}, len(manifest.Capabilities))
	seenCategories := make(map[Category]struct{}, len(categoryOrder))
	for index, entry := range manifest.Capabilities {
		if err := validateCapability(entry); err != nil {
			return fmt.Errorf("capability %d: %w", index, err)
		}
		if _, exists := seenIDs[entry.ID]; exists {
			return fmt.Errorf("duplicate capability id %q", entry.ID)
		}
		seenIDs[entry.ID] = struct{}{}
		seenCategories[entry.Category] = struct{}{}
	}
	for _, category := range categoryOrder {
		if _, exists := seenCategories[category]; !exists {
			return fmt.Errorf("category %q has no capabilities", category)
		}
	}

	seenExclusions := make(map[string]struct{}, len(manifest.Exclusions))
	for index, exclusion := range manifest.Exclusions {
		if _, known := knownExclusions[exclusion.ID]; !known {
			return fmt.Errorf("exclusion %d has unknown id %q", index, exclusion.ID)
		}
		if _, exists := seenExclusions[exclusion.ID]; exists {
			return fmt.Errorf("duplicate exclusion id %q", exclusion.ID)
		}
		seenExclusions[exclusion.ID] = struct{}{}
		if strings.TrimSpace(exclusion.Title) == "" || strings.TrimSpace(exclusion.Reason) == "" {
			return fmt.Errorf("exclusion %q requires title and reason", exclusion.ID)
		}
		if err := validateRelativePath(exclusion.DecisionRef); err != nil {
			return fmt.Errorf("exclusion %q decisionRef: %w", exclusion.ID, err)
		}
	}
	return nil
}

func validateCapability(entry Capability) error {
	if strings.TrimSpace(entry.ID) == "" {
		return fmt.Errorf("id is empty")
	}
	if !strings.HasPrefix(entry.ID, string(entry.Category)+".") {
		return fmt.Errorf("id %q must start with category %q", entry.ID, entry.Category+".")
	}
	if strings.TrimSpace(entry.Title) == "" {
		return fmt.Errorf("%q has an empty title", entry.ID)
	}
	if !knownCategory(entry.Category) {
		return fmt.Errorf("%q has invalid category %q", entry.ID, entry.Category)
	}
	if err := validateObservableContracts(entry.ObservableContracts); err != nil {
		return fmt.Errorf("capability %q observableContracts: %w", entry.ID, err)
	}
	if err := validateUpstreamReferences(entry.UpstreamRefs); err != nil {
		return fmt.Errorf("capability %q upstreamRefs: %w", entry.ID, err)
	}
	switch entry.Status {
	case StatusPassing:
		if len(entry.ProductionRefs) == 0 || len(entry.TestRefs) == 0 {
			return fmt.Errorf("passing capability %q requires productionRefs and testRefs", entry.ID)
		}
		if len(entry.Dimensions.TestKinds) == 0 {
			return fmt.Errorf("passing capability %q requires a testKinds dimension", entry.ID)
		}
	case StatusPartial:
		if len(entry.ProductionRefs) == 0 && len(entry.TestRefs) == 0 {
			return fmt.Errorf("partial capability %q has no implementation or test evidence", entry.ID)
		}
		if strings.TrimSpace(entry.Notes) == "" {
			return fmt.Errorf("partial capability %q requires notes describing the gap", entry.ID)
		}
	case StatusMissing:
		if strings.TrimSpace(entry.Notes) == "" {
			return fmt.Errorf("missing capability %q requires notes describing the gap", entry.ID)
		}
	default:
		return fmt.Errorf("%q has invalid status %q", entry.ID, entry.Status)
	}
	if len(entry.TestRefs) > 0 && len(entry.Dimensions.TestKinds) == 0 {
		return fmt.Errorf("capability %q has testRefs but no testKinds dimension", entry.ID)
	}
	if err := validateReferences(entry.ProductionRefs, false); err != nil {
		return fmt.Errorf("capability %q productionRefs: %w", entry.ID, err)
	}
	if err := validateReferences(entry.TestRefs, true); err != nil {
		return fmt.Errorf("capability %q testRefs: %w", entry.ID, err)
	}
	if err := validateDimensions(entry.Dimensions); err != nil {
		return fmt.Errorf("capability %q dimensions: %w", entry.ID, err)
	}
	if entry.Category == CategoryTransports && len(entry.Dimensions.Transports) == 0 {
		return fmt.Errorf("transport capability %q has no transport dimension", entry.ID)
	}
	if entry.Category == CategoryNativeStorage && len(entry.Dimensions.StorageBackends) == 0 {
		return fmt.Errorf("native-storage capability %q has no storageBackends dimension", entry.ID)
	}
	return nil
}

func validateObservableContracts(contracts []ObservableContract) error {
	if len(contracts) == 0 {
		return fmt.Errorf("at least one observable contract is required")
	}
	seenIDs := make(map[string]struct{}, len(contracts))
	seenAssertions := make(map[string]struct{})
	for index, contract := range contracts {
		if !validContractID(contract.ID) {
			return fmt.Errorf("contract %d has invalid id %q", index, contract.ID)
		}
		if _, exists := seenIDs[contract.ID]; exists {
			return fmt.Errorf("duplicate contract id %q", contract.ID)
		}
		seenIDs[contract.ID] = struct{}{}
		if len(contract.Assertions) < 2 {
			return fmt.Errorf("contract %q requires at least two assertions", contract.ID)
		}
		for assertionIndex, assertion := range contract.Assertions {
			if strings.TrimSpace(assertion) == "" || assertion != strings.TrimSpace(assertion) {
				return fmt.Errorf("contract %q assertion %d is empty or not trimmed", contract.ID, assertionIndex)
			}
			if len(assertion) < 12 {
				return fmt.Errorf("contract %q assertion %d is too short", contract.ID, assertionIndex)
			}
			if _, exists := seenAssertions[assertion]; exists {
				return fmt.Errorf("duplicate assertion %q", assertion)
			}
			seenAssertions[assertion] = struct{}{}
		}
	}
	return nil
}

func validContractID(value string) bool {
	if value == "" || strings.Contains(value, "--") {
		return false
	}
	for index, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9' && index > 0:
		case character == '-' && index > 0 && index < len(value)-1:
		default:
			return false
		}
	}
	return true
}

func validateUpstreamReferences(references []UpstreamReference) error {
	if len(references) == 0 {
		return fmt.Errorf("at least one upstream reference is required")
	}
	seenPaths := make(map[string]struct{}, len(references))
	for index, reference := range references {
		if err := validateUpstreamPath(reference.Path); err != nil {
			return fmt.Errorf("reference %d: %w", index, err)
		}
		if _, exists := seenPaths[reference.Path]; exists {
			return fmt.Errorf("duplicate path %q", reference.Path)
		}
		seenPaths[reference.Path] = struct{}{}
		if len(reference.Cases) == 0 {
			return fmt.Errorf("reference %q has no cases", reference.Path)
		}
		seenCases := make(map[string]struct{}, len(reference.Cases))
		for caseIndex, testCase := range reference.Cases {
			if strings.TrimSpace(testCase) == "" || testCase != strings.TrimSpace(testCase) {
				return fmt.Errorf("reference %q case %d is empty or not trimmed", reference.Path, caseIndex)
			}
			if _, exists := seenCases[testCase]; exists {
				return fmt.Errorf("reference %q has duplicate case %q", reference.Path, testCase)
			}
			seenCases[testCase] = struct{}{}
		}
	}
	return nil
}

func validateReferences(references []string, tests bool) error {
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if err := validateRelativePath(reference); err != nil {
			return err
		}
		if !strings.HasSuffix(reference, ".go") {
			return fmt.Errorf("%q is not a Go source file", reference)
		}
		if tests != strings.HasSuffix(reference, "_test.go") {
			if tests {
				return fmt.Errorf("%q is not a Go test file", reference)
			}
			return fmt.Errorf("%q is a test file, not production code", reference)
		}
		if _, exists := seen[reference]; exists {
			return fmt.Errorf("duplicate reference %q", reference)
		}
		seen[reference] = struct{}{}
	}
	return nil
}

func validateRelativePath(value string) error {
	if err := validateCleanRelativePath(value); err != nil {
		return err
	}
	root, _, _ := strings.Cut(value, "/")
	switch root {
	case "compat", "node_modules":
		return fmt.Errorf("path %q references a non-Go support tree", value)
	}
	return nil
}

func validateUpstreamPath(value string) error {
	return validateCleanRelativePath(value)
}

func validateCleanRelativePath(value string) error {
	if value == "" {
		return fmt.Errorf("path is empty")
	}
	if filepath.IsAbs(value) || strings.Contains(value, "\\") {
		return fmt.Errorf("path %q must be a slash-separated repository-relative path", value)
	}
	clean := pathpkg.Clean(value)
	if clean != value || clean == "." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path %q is not clean and repository-relative", value)
	}
	return nil
}

func validateDimensions(dimensions Dimensions) error {
	if err := validateDimensionValues("transports", dimensions.Transports, allowedTransports); err != nil {
		return err
	}
	if err := validateDimensionValues("storageBackends", dimensions.StorageBackends, allowedStorageBackends); err != nil {
		return err
	}
	if err := validateDimensionValues("testKinds", dimensions.TestKinds, allowedTestKinds); err != nil {
		return err
	}
	return nil
}

func validateDimensionValues(name string, values []string, allowed map[string]struct{}) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := allowed[value]; !exists {
			return fmt.Errorf("%s contains invalid value %q", name, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate value %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func knownCategory(category Category) bool {
	for _, known := range categoryOrder {
		if category == known {
			return true
		}
	}
	return false
}

// ValidateReferences verifies that every evidence and decision reference is a
// regular file below root. It intentionally does not inspect the optional
// preserved upstream tree, so ordinary Go validation remains self-contained.
func (manifest Manifest) ValidateReferences(root string) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("repository root is empty")
	}
	for _, entry := range manifest.Capabilities {
		for _, reference := range append(append([]string(nil), entry.ProductionRefs...), entry.TestRefs...) {
			if err := validateRegularFile(root, reference); err != nil {
				return fmt.Errorf("capability %q reference %q: %w", entry.ID, reference, err)
			}
		}
	}
	for _, exclusion := range manifest.Exclusions {
		if err := validateRegularFile(root, exclusion.DecisionRef); err != nil {
			return fmt.Errorf("exclusion %q decisionRef %q: %w", exclusion.ID, exclusion.DecisionRef, err)
		}
	}
	return nil
}

// ValidateUpstreamReferences verifies preserved snapshot paths and exact case
// substrings. Callers opt into this audit explicitly; the normal Go test suite
// and default report do not require the snapshot to be present.
func (manifest Manifest) ValidateUpstreamReferences(snapshotRoot string) error {
	if strings.TrimSpace(snapshotRoot) == "" {
		return fmt.Errorf("snapshot root is empty")
	}
	contents := make(map[string][]byte)
	for _, entry := range manifest.Capabilities {
		for _, reference := range entry.UpstreamRefs {
			content, exists := contents[reference.Path]
			if !exists {
				absolute := filepath.Join(snapshotRoot, filepath.FromSlash(reference.Path))
				info, err := os.Stat(absolute)
				if err != nil {
					return fmt.Errorf("capability %q upstream reference %q: %w", entry.ID, reference.Path, err)
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("capability %q upstream reference %q: not a regular file", entry.ID, reference.Path)
				}
				content, err = os.ReadFile(absolute)
				if err != nil {
					return fmt.Errorf("capability %q upstream reference %q: %w", entry.ID, reference.Path, err)
				}
				contents[reference.Path] = content
			}
			for _, testCase := range reference.Cases {
				if !strings.Contains(string(content), testCase) {
					return fmt.Errorf(
						"capability %q upstream reference %q does not contain case %q",
						entry.ID, reference.Path, testCase,
					)
				}
			}
		}
	}
	return nil
}

func validateRegularFile(root, reference string) error {
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(reference)))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	return nil
}

// Categories returns the stable report order.
func Categories() []Category {
	return append([]Category(nil), categoryOrder...)
}

// KnownExclusionIDs returns the closed exclusion catalog in lexical order.
func KnownExclusionIDs() []string {
	ids := make([]string, 0, len(knownExclusions))
	for id := range knownExclusions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
