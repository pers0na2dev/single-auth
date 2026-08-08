package main

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGeneratedReferenceIsCurrentCompleteAndDeterministic(t *testing.T) {
	root := repositoryRoot(t)
	packages, err := loadPackages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) == 0 {
		t.Fatal("server package inventory is empty")
	}
	for _, pkg := range packages {
		if len(pkg.ExportedSymbols) == 0 {
			t.Fatalf("%s has no audited exported symbols", pkg.Info.ImportPath)
		}
		if !documentServerPackage(pkg.Info) {
			t.Fatalf("excluded package %s reached the generated inventory", pkg.Info.ImportPath)
		}
	}

	first := renderReference(packages)
	second := renderReference(packages)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("rendering the same server API inventory is not deterministic")
	}
	directory := filepath.Join(root, "docs", "content", "docs", "reference", "packages")
	if err := checkUnexpectedReferencePages(directory, first); err != nil {
		t.Fatal(err)
	}
	if err := checkGeneratedReference(directory, first); err != nil {
		t.Fatal(err)
	}
}

func TestServerPackageSourceExclusions(t *testing.T) {
	packages := []listedPackage{
		{ImportPath: "github.com/pers0na2dev/single-auth", Name: "singleauth", GoFiles: []string{"auth.go"}},
		{ImportPath: "github.com/pers0na2dev/single-auth/plugins/admin", Name: "admin", GoFiles: []string{"plugin.go"}},
		{ImportPath: "github.com/pers0na2dev/single-auth/internal/conformance/capability", Name: "capability", GoFiles: []string{"manifest.go"}},
		{ImportPath: "github.com/pers0na2dev/single-auth/storage/adaptertest", Name: "adaptertest", GoFiles: []string{"suite.go"}},
		{ImportPath: "github.com/pers0na2dev/single-auth/transport/internal/testsuite", Name: "testsuite", GoFiles: []string{"suite.go"}},
	}
	want := []bool{true, true, false, false, false}
	for index, pkg := range packages {
		if got := documentServerPackage(pkg); got != want[index] {
			t.Errorf("documentServerPackage(%q) = %t, want %t", pkg.ImportPath, got, want[index])
		}
	}
}

func TestPackageGroupsFollowVNextLayout(t *testing.T) {
	tests := map[string]string{
		"github.com/pers0na2dev/single-auth":                               "Entry point",
		"github.com/pers0na2dev/single-auth/core":                          "Core runtime",
		"github.com/pers0na2dev/single-auth/core/engine":                   "Core runtime",
		"github.com/pers0na2dev/single-auth/security/crypto":               "Security",
		"github.com/pers0na2dev/single-auth/protocol/oauth2":               "Protocols",
		"github.com/pers0na2dev/single-auth/storage/secondary/redis":       "Storage",
		"github.com/pers0na2dev/single-auth/transport/fiber":               "Transports",
		"github.com/pers0na2dev/single-auth/observability/instrumentation": "Observability",
		"github.com/pers0na2dev/single-auth/plugins/passkey":               "Plugins",
	}
	for importPath, want := range tests {
		if got := packageGroup(importPath); got != want {
			t.Errorf("packageGroup(%q) = %q, want %q", importPath, got, want)
		}
	}
}

func TestGoDeclarationsKeepExactIdentifiersAndFormatFilteredMembers(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "api.go", `package sample

// BehaviorResult is deliberately named.
type BehaviorResult struct {
	Visible string
	hidden string
}
`, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	astPackage := &ast.Package{Name: "sample", Files: map[string]*ast.File{"api.go": file}}
	documented := doc.New(astPackage, "sample", 0)
	var output strings.Builder
	writeGoDeclaration(&output, fileSet, documented.Types[0].Decl)
	got := output.String()
	if !strings.Contains(got, "type BehaviorResult struct") {
		t.Fatalf("declaration identifier was rewritten:\n%s", got)
	}
	if strings.Contains(got, "CompatibilityResult") {
		t.Fatalf("declaration contains rewritten identifier:\n%s", got)
	}
	if !strings.Contains(got, "\n\t// contains filtered or unexported fields\n}") {
		t.Fatalf("filtered-member marker is malformed:\n%s", got)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
