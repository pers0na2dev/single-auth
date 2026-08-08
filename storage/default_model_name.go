package storage

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultModelNameOptions are the inputs accepted by reference implementation's
// initGetDefaultModelName helper. Schema keys are the canonical model names;
// ModelSchema.ModelName values are their optional physical aliases.
type DefaultModelNameOptions struct {
	Schema    Schema
	UsePlural bool
}

// DefaultModelNameResolver maps either a canonical schema key or a physical
// model-name alias back to the canonical key.
type DefaultModelNameResolver func(model string) (string, error)

// ModelResolutionError preserves reference implementation's public error message while
// still allowing callers to match storage.ErrModelNotFound with errors.Is.
type ModelResolutionError struct {
	Model string
}

func (e *ModelResolutionError) Error() string {
	return fmt.Sprintf("Model %q not found in schema", e.Model)
}

func (e *ModelResolutionError) Unwrap() error {
	return ErrModelNotFound
}

// InitGetDefaultModelName is the Go equivalent of reference implementation's
// initGetDefaultModelName. Exact schema-key matches deliberately win over
// aliases so a remapped model cannot redirect internal canonical queries.
func InitGetDefaultModelName(options DefaultModelNameOptions) DefaultModelNameResolver {
	resolve := func(candidate string) (string, bool) {
		if _, exists := options.Schema.Models[candidate]; exists {
			return candidate, true
		}

		// JavaScript objects retain insertion order, whereas a Go map does not.
		// Sorting keeps fallback alias lookup deterministic if a malformed schema
		// assigns the same physical name to multiple canonical models.
		canonicalNames := make([]string, 0, len(options.Schema.Models))
		for canonical := range options.Schema.Models {
			canonicalNames = append(canonicalNames, canonical)
		}
		sort.Strings(canonicalNames)
		for _, canonical := range canonicalNames {
			if options.Schema.Models[canonical].ModelName == candidate {
				return canonical, true
			}
		}
		return "", false
	}

	return func(model string) (string, error) {
		if options.UsePlural && strings.HasSuffix(model, "s") {
			if canonical, exists := resolve(strings.TrimSuffix(model, "s")); exists {
				return canonical, nil
			}
		}
		if canonical, exists := resolve(model); exists {
			return canonical, nil
		}
		return "", &ModelResolutionError{Model: model}
	}
}
