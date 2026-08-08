// Command go-test-report converts `go test -json` output into deterministic
// conformance evidence.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pers0na2dev/single-auth/internal/conformance/gotestreport"
)

type pathList []string

func (paths *pathList) String() string {
	return strings.Join(*paths, ",")
}

func (paths *pathList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("path is empty")
	}
	*paths = append(*paths, value)
	return nil
}

func main() {
	outputPath := flag.String("output", "", "write JSON report to this file instead of stdout")
	compatibilityPath := flag.String("compatibility-map", "", "compare exact IDs with passing go-test entries in this compatibility map")
	var candidatePaths pathList
	flag.Var(&candidatePaths, "candidate-fragment", "also validate a pending compatibility-update fragment; may be repeated")
	candidateOnly := flag.Bool("candidate-only", false, "validate only candidate fragments, ignoring accepted IDs outside a focused test run")
	requirePassing := flag.Bool("require-passing-map", false, "fail unless every expected accepted/candidate Go ID was observed exactly once in a passing test")
	flag.Parse()
	if *requirePassing && *compatibilityPath == "" {
		fatal(fmt.Errorf("-require-passing-map requires -compatibility-map"))
	}
	if len(candidatePaths) > 0 && *compatibilityPath == "" {
		fatal(fmt.Errorf("-candidate-fragment requires -compatibility-map"))
	}
	if *candidateOnly && len(candidatePaths) == 0 {
		fatal(fmt.Errorf("-candidate-only requires -candidate-fragment"))
	}

	report, err := gotestreport.Parse(os.Stdin)
	if err != nil {
		fatal(err)
	}
	if *compatibilityPath != "" {
		file, openErr := os.Open(*compatibilityPath)
		if openErr != nil {
			fatal(fmt.Errorf("open compatibility map: %w", openErr))
		}
		candidateFiles := make([]*os.File, 0, len(candidatePaths))
		candidateReaders := make([]io.Reader, 0, len(candidatePaths))
		for _, path := range candidatePaths {
			candidate, candidateErr := os.Open(path)
			if candidateErr != nil {
				fatal(fmt.Errorf("open candidate fragment: %w", candidateErr))
			}
			candidateFiles = append(candidateFiles, candidate)
			candidateReaders = append(candidateReaders, candidate)
		}
		if *candidateOnly {
			err = gotestreport.CompareCandidateFragments(&report, file, candidateReaders...)
		} else {
			err = gotestreport.ComparePassingGoWithCandidates(&report, file, candidateReaders...)
		}
		closeErr := file.Close()
		for _, candidate := range candidateFiles {
			if candidateErr := candidate.Close(); candidateErr != nil && closeErr == nil {
				closeErr = candidateErr
			}
		}
		if err != nil {
			fatal(err)
		}
		if closeErr != nil {
			fatal(fmt.Errorf("close compatibility map: %w", closeErr))
		}
	}

	var writer io.Writer = os.Stdout
	var output *os.File
	if *outputPath != "" {
		output, err = os.Create(*outputPath)
		if err != nil {
			fatal(fmt.Errorf("create output: %w", err))
		}
		writer = output
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fatal(fmt.Errorf("encode report: %w", err))
	}
	if output != nil {
		if err := output.Close(); err != nil {
			fatal(fmt.Errorf("close output: %w", err))
		}
	}
	if *requirePassing && !gotestreport.PassingMapSatisfied(report.Compatibility) {
		fatal(fmt.Errorf("accepted Go compatibility IDs were not all observed exactly once in passing tests"))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "go-test-report:", err)
	os.Exit(1)
}
