package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	markdownLink = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)
	inlineCode   = regexp.MustCompile("`[^`\\n]*`")
)

type auditStatistics struct {
	Pages int
	Links int
}

func main() {
	root, err := os.Getwd()
	check(err)
	contentRoot := filepath.Join(root, "docs", "content", "docs")
	statistics, failures, err := auditDocumentation(contentRoot)
	check(err)

	if len(failures) != 0 {
		sort.Strings(failures)
		for _, failure := range failures {
			fmt.Fprintln(os.Stderr, failure)
		}
		os.Exit(1)
	}
	fmt.Printf("checked %d pages and %d internal links in %s\n", statistics.Pages, statistics.Links, relative(root, contentRoot))
}

func auditDocumentation(contentRoot string) (auditStatistics, []string, error) {
	var statistics auditStatistics
	var failures []string

	err := filepath.WalkDir(contentRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".md" {
			statistics.Pages++
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			content := stripCode(string(data))
			for _, match := range markdownLink.FindAllStringSubmatch(content, -1) {
				if linkNeedsValidation(match[1]) {
					statistics.Links++
				}
				if failure := validateLink(contentRoot, path, match[1]); failure != "" {
					failures = append(failures, failure)
				}
			}
		}
		return nil
	})
	return statistics, failures, err
}

func linkNeedsValidation(raw string) bool {
	target := strings.TrimSpace(raw)
	if target == "" || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "mailto:") ||
		strings.HasPrefix(target, "tel:") {
		return false
	}
	return !strings.HasPrefix(target, "/") || target == "/docs" || strings.HasPrefix(target, "/docs/")
}

func stripCode(input string) string {
	var output strings.Builder
	inFence := false
	for _, line := range strings.Split(input, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			output.WriteByte('\n')
			continue
		}
		if inFence {
			output.WriteByte('\n')
			continue
		}
		output.WriteString(inlineCode.ReplaceAllString(line, ""))
		output.WriteByte('\n')
	}
	return output.String()
}

func validateLink(contentRoot, source, raw string) string {
	target := strings.TrimSpace(raw)
	if target == "" || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "mailto:") ||
		strings.HasPrefix(target, "tel:") {
		return ""
	}
	if index := strings.IndexAny(target, "?#"); index >= 0 {
		target = target[:index]
	}
	if target == "" {
		return ""
	}

	var candidate string
	if target == "/docs" {
		candidate = filepath.Join(contentRoot, "index")
	} else if strings.HasPrefix(target, "/docs/") {
		candidate = filepath.Join(contentRoot, filepath.FromSlash(strings.TrimPrefix(target, "/docs/")))
	} else if strings.HasPrefix(target, "/") {
		return ""
	} else {
		candidate = filepath.Join(filepath.Dir(source), filepath.FromSlash(target))
	}
	if !pathWithin(contentRoot, candidate) {
		root := filepath.Dir(filepath.Dir(filepath.Dir(contentRoot)))
		return fmt.Sprintf("%s: documentation link %q escapes the documentation root", relative(root, source), raw)
	}
	if pageExists(candidate) {
		return ""
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(contentRoot)))
	return fmt.Sprintf("%s: broken documentation link %q", relative(root, source), raw)
}

func pathWithin(root, path string) bool {
	relativePath, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil || relativePath == ".." {
		return false
	}
	return !strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) && !filepath.IsAbs(relativePath)
}

func pageExists(candidate string) bool {
	if info, err := os.Stat(candidate); err == nil {
		if info.IsDir() {
			return regularFile(filepath.Join(candidate, "index.md"))
		}
		return !info.IsDir()
	}
	if filepath.Ext(candidate) == "" && regularFile(candidate+".md") {
		return true
	}
	return regularFile(filepath.Join(candidate, "index.md"))
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func relative(root, path string) string {
	value, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(value)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
