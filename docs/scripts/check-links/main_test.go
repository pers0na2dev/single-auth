package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckedInDocumentationLinks(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	statistics, failures, err := auditDocumentation(filepath.Join(root, "docs", "content", "docs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("documentation audit failures:\n%s", strings.Join(failures, "\n"))
	}
	if statistics.Pages == 0 || statistics.Links == 0 {
		t.Fatalf("incomplete audit statistics: %+v", statistics)
	}
}

func TestDocumentationPagesHaveFumadocsTitles(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contentRoot := filepath.Join(root, "docs", "content", "docs")
	pages := 0
	err = filepath.WalkDir(contentRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}
		pages++
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !strings.HasPrefix(string(data), "---\ntitle: ") {
			t.Errorf("%s must start with Fumadocs title frontmatter", relative(root, path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pages == 0 {
		t.Fatal("documentation page inventory is empty")
	}
}

func TestPathWithinDocumentationRoot(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "repo", "docs", "content", "docs")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "root", path: root, want: true},
		{name: "nested", path: filepath.Join(root, "plugins", "sso"), want: true},
		{name: "parent", path: filepath.Join(root, "..", "README.md"), want: false},
		{name: "prefix sibling", path: root + "-old/index.md", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pathWithin(root, test.path); got != test.want {
				t.Fatalf("pathWithin(%q, %q) = %t, want %t", root, test.path, got, test.want)
			}
		})
	}
}

func TestStripCodeIgnoresLinksInsideFencesAndInlineCode(t *testing.T) {
	input := "[kept](./page)\n`[inline](./ignored)`\n```go\n[code](./ignored)\n```\n"
	stripped := stripCode(input)
	if !strings.Contains(stripped, "[kept](./page)") {
		t.Fatal("ordinary Markdown link was stripped")
	}
	if strings.Contains(stripped, "./ignored") {
		t.Fatalf("code link survived stripping:\n%s", stripped)
	}
}
