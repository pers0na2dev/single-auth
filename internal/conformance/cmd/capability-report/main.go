// Command capability-report validates and summarizes the native Go capability
// map. Default operation has no dependency on an upstream source tree or a
// JavaScript runtime; preserved source verification is an explicit read-only
// option.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pers0na2dev/single-auth/internal/conformance/capability"
)

func main() {
	manifestPath := flag.String("manifest", "conformance/capability-map.json", "path to the Go capability map")
	repositoryRoot := flag.String("root", "", "repository root used to verify production and test references")
	upstreamRoot := flag.String("upstream-root", "", "optional preserved snapshot root used to verify source paths and case substrings")
	jsonOutput := flag.Bool("json", false, "print the report as JSON")
	flag.Parse()

	manifest, err := capability.Load(*manifestPath)
	if err != nil {
		fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		fatal(fmt.Errorf("validate capability map: %w", err))
	}
	root := *repositoryRoot
	if root == "" {
		root, err = inferRepositoryRoot(*manifestPath)
		if err != nil {
			fatal(err)
		}
	}
	if err := manifest.ValidateReferences(root); err != nil {
		fatal(fmt.Errorf("validate capability references: %w", err))
	}
	if *upstreamRoot != "" {
		if err := manifest.ValidateUpstreamReferences(*upstreamRoot); err != nil {
			fatal(fmt.Errorf("validate upstream references: %w", err))
		}
	}

	report := capability.BuildReport(manifest)
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			fatal(fmt.Errorf("encode report: %w", err))
		}
		return
	}
	if err := capability.WriteText(os.Stdout, report); err != nil {
		fatal(fmt.Errorf("write report: %w", err))
	}
}

func inferRepositoryRoot(manifestPath string) (string, error) {
	absolute, err := filepath.Abs(manifestPath)
	if err != nil {
		return "", fmt.Errorf("resolve manifest path: %w", err)
	}
	directory := filepath.Dir(absolute)
	if filepath.Base(directory) == "conformance" {
		return filepath.Dir(directory), nil
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	return workingDirectory, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "capability-report:", err)
	os.Exit(1)
}
