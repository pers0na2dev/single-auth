package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const modulePath = "github.com/pers0na2dev/single-auth"

type listedPackage struct {
	ImportPath string
	Dir        string
	Name       string
	GoFiles    []string
	CgoFiles   []string
}

type documentedPackage struct {
	Info            listedPackage
	Doc             *doc.Package
	FileSet         *token.FileSet
	Slug            string
	ExportedSymbols []string
}

func main() {
	checkOnly := flag.Bool("check", false, "verify that the checked-in reference matches the current server API")
	flag.Parse()

	root, err := os.Getwd()
	checkReference(err)
	packages, err := loadPackages(root)
	checkReference(err)

	directory := filepath.Join(root, "docs", "content", "docs", "reference", "packages")
	generated := renderReference(packages)
	checkReference(checkUnexpectedReferencePages(directory, generated))
	if *checkOnly {
		checkReference(checkGeneratedReference(directory, generated))
	} else {
		checkReference(os.MkdirAll(directory, 0o755))
		for name, contents := range generated {
			checkReference(os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o644))
		}
	}

	action := "generated"
	if *checkOnly {
		action = "verified"
	}
	fmt.Printf("%s %d server packages and %d exported declarations/methods\n", action, len(packages), countExportedSymbols(packages))
}

func renderReference(packages []documentedPackage) map[string]string {
	generated := make(map[string]string, len(packages)+2)
	for _, pkg := range packages {
		generated[pkg.Slug+".md"] = renderPackage(pkg)
	}
	generated["index.md"] = renderPackageIndex(packages)
	generated["meta.json"] = renderPackageNavigation(packages)
	return generated
}

func checkUnexpectedReferencePages(directory string, expected map[string]string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var unexpected []string
	for _, entry := range entries {
		extension := filepath.Ext(entry.Name())
		if entry.IsDir() || (extension != ".md" && extension != ".mdx" && entry.Name() != "meta.json") {
			continue
		}
		if _, ok := expected[entry.Name()]; !ok {
			unexpected = append(unexpected, entry.Name())
		}
	}
	if len(unexpected) == 0 {
		return nil
	}
	sort.Strings(unexpected)
	return fmt.Errorf(
		"stale generated reference pages: %s; move each resolved path to Trash before regenerating",
		strings.Join(unexpected, ", "),
	)
}

func checkGeneratedReference(directory string, expected map[string]string) error {
	var mismatches []string
	for name, contents := range expected {
		path := filepath.Join(directory, name)
		actual, err := os.ReadFile(path)
		if err != nil {
			mismatches = append(mismatches, name+": "+err.Error())
			continue
		}
		if string(actual) != contents {
			mismatches = append(mismatches, name+": generated content differs")
		}
	}
	if len(mismatches) == 0 {
		return nil
	}
	sort.Strings(mismatches)
	return fmt.Errorf("Go API reference is stale:\n%s", strings.Join(mismatches, "\n"))
}

func countExportedSymbols(packages []documentedPackage) int {
	total := 0
	for _, pkg := range packages {
		total += len(pkg.ExportedSymbols)
	}
	return total
}

func loadPackages(root string) ([]documentedPackage, error) {
	command := exec.Command("go", "list", "-json", "./...")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go list: %s", strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	var result []documentedPackage
	for {
		var info listedPackage
		if err := decoder.Decode(&info); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		if !documentServerPackage(info) {
			continue
		}
		parsed, fileSet, sourceSymbols, err := parsePackage(info)
		if err != nil {
			return nil, err
		}
		if err := verifyDocumentedSymbols(info.ImportPath, parsed, sourceSymbols); err != nil {
			return nil, err
		}
		documented := documentedSymbols(parsed)
		result = append(result, documentedPackage{
			Info:            info,
			Doc:             parsed,
			FileSet:         fileSet,
			Slug:            packageSlug(info.ImportPath),
			ExportedSymbols: documented,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Info.ImportPath < result[right].Info.ImportPath
	})
	return result, nil
}

func documentServerPackage(info listedPackage) bool {
	if info.Name == "main" || (info.ImportPath != modulePath && !strings.HasPrefix(info.ImportPath, modulePath+"/")) {
		return false
	}
	relative := strings.TrimPrefix(info.ImportPath, modulePath)
	for _, excluded := range []string{
		"/conformance",
		"/docs",
		"/e2e",
		"/internal",
		"/storage/adaptertest",
		"/testdata",
	} {
		if relative == excluded || strings.HasPrefix(relative, excluded+"/") {
			return false
		}
	}
	if strings.Contains(relative, "/internal/") || strings.Contains(relative, "/testdata/") ||
		strings.HasSuffix(relative, "/testsuite") {
		return false
	}
	return len(info.GoFiles)+len(info.CgoFiles) != 0
}

func parsePackage(info listedPackage) (*doc.Package, *token.FileSet, []string, error) {
	fileSet := token.NewFileSet()
	files := make(map[string]*ast.File, len(info.GoFiles)+len(info.CgoFiles))
	for _, name := range append(append([]string{}, info.GoFiles...), info.CgoFiles...) {
		path := filepath.Join(info.Dir, name)
		file, err := parser.ParseFile(fileSet, path, nil, parser.ParseComments)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		files[path] = file
	}
	astPackage := &ast.Package{Name: info.Name, Files: files}
	symbols := exportedSourceSymbols(astPackage)
	return doc.New(astPackage, info.ImportPath, 0), fileSet, symbols, nil
}

func exportedSourceSymbols(pkg *ast.Package) []string {
	symbols := make(map[string]struct{})
	for _, file := range pkg.Files {
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.GenDecl:
				kind := strings.ToLower(value.Tok.String())
				for _, spec := range value.Specs {
					switch item := spec.(type) {
					case *ast.ValueSpec:
						for _, name := range item.Names {
							if ast.IsExported(name.Name) {
								symbols[kind+":"+name.Name] = struct{}{}
							}
						}
					case *ast.TypeSpec:
						if ast.IsExported(item.Name.Name) {
							symbols["type:"+item.Name.Name] = struct{}{}
						}
					}
				}
			case *ast.FuncDecl:
				if !ast.IsExported(value.Name.Name) {
					continue
				}
				if value.Recv == nil {
					symbols["func:"+value.Name.Name] = struct{}{}
					continue
				}
				receiver := receiverTypeName(value.Recv.List[0].Type)
				if ast.IsExported(receiver) {
					symbols["method:"+receiver+"."+value.Name.Name] = struct{}{}
				}
			}
		}
	}
	return sortedSymbolSet(symbols)
}

func receiverTypeName(value ast.Expr) string {
	switch value := value.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return receiverTypeName(value.X)
	case *ast.IndexExpr:
		return receiverTypeName(value.X)
	case *ast.IndexListExpr:
		return receiverTypeName(value.X)
	default:
		return ""
	}
}

func documentedSymbols(pkg *doc.Package) []string {
	symbols := make(map[string]struct{})
	addValues := func(kind string, values []*doc.Value) {
		for _, value := range values {
			for _, name := range value.Names {
				symbols[kind+":"+name] = struct{}{}
			}
		}
	}
	addFunctions := func(functions []*doc.Func) {
		for _, function := range functions {
			symbols["func:"+function.Name] = struct{}{}
		}
	}
	addValues("const", pkg.Consts)
	addValues("var", pkg.Vars)
	addFunctions(pkg.Funcs)
	for _, typ := range pkg.Types {
		symbols["type:"+typ.Name] = struct{}{}
		addValues("const", typ.Consts)
		addValues("var", typ.Vars)
		addFunctions(typ.Funcs)
		for _, method := range typ.Methods {
			symbols["method:"+typ.Name+"."+method.Name] = struct{}{}
		}
	}
	return sortedSymbolSet(symbols)
}

func sortedSymbolSet(symbols map[string]struct{}) []string {
	result := make([]string, 0, len(symbols))
	for symbol := range symbols {
		result = append(result, symbol)
	}
	sort.Strings(result)
	return result
}

func verifyDocumentedSymbols(importPath string, pkg *doc.Package, source []string) error {
	documented := documentedSymbols(pkg)
	documentedSet := make(map[string]struct{}, len(documented))
	for _, symbol := range documented {
		documentedSet[symbol] = struct{}{}
	}
	var missing []string
	for _, symbol := range source {
		if _, ok := documentedSet[symbol]; !ok {
			missing = append(missing, symbol)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf(
		"exported symbol coverage mismatch for %s; missing: %s",
		importPath,
		strings.Join(missing, ", "),
	)
}

func packageSlug(importPath string) string {
	if importPath == modulePath {
		return "root"
	}
	return strings.ReplaceAll(strings.TrimPrefix(importPath, modulePath+"/"), "/", "--")
}

var packageGroupOrder = []string{
	"Entry point",
	"Core runtime",
	"Security",
	"Protocols",
	"Storage",
	"Transports",
	"Observability",
	"Plugins",
	"Utilities",
}

func renderPackageIndex(packages []documentedPackage) string {
	groups := map[string][]documentedPackage{}
	for _, pkg := range packages {
		group := packageGroup(pkg.Info.ImportPath)
		groups[group] = append(groups[group], pkg)
	}
	var output strings.Builder
	output.WriteString(`---
title: "Go package reference"
---

Generated reference for every exported symbol in the supported server-side Go packages.

This reference is generated from the current Go source. It includes exported constants, variables, types, functions, and methods. Narrative guides explain lifecycle and policy; these pages provide exact declarations.

> **Info: Server API only**
>
> Browser and framework clients are documented separately in the [JavaScript client guide](../../javascript-client/index.md). Internal implementation packages, conformance machinery, commands, and test fixtures are excluded from this server-package reference.

`)
	for _, group := range packageGroupOrder {
		entries := groups[group]
		if len(entries) == 0 {
			continue
		}
		output.WriteString("## " + group + "\n\n")
		for _, pkg := range entries {
			description := firstSentence(pkg.Doc.Doc)
			if description == "" {
				description = "Exported server-side Go API."
			}
			output.WriteString(fmt.Sprintf("- [`%s`](./%s.md) — %s\n", pkg.Info.ImportPath, pkg.Slug, sanitizeMarkdown(description)))
		}
		output.WriteString("\n")
	}
	output.WriteString("Regenerate after public API changes with `go run ./docs/scripts/go-api-reference` from the repository root. Verify checked-in output with `go run ./docs/scripts/go-api-reference -check`.\n")
	return output.String()
}

func renderPackageNavigation(packages []documentedPackage) string {
	groups := make(map[string][]documentedPackage)
	for _, pkg := range packages {
		group := packageGroup(pkg.Info.ImportPath)
		groups[group] = append(groups[group], pkg)
	}
	pages := make([]string, 0, len(packages))
	for _, group := range packageGroupOrder {
		for _, pkg := range groups[group] {
			pages = append(pages, pkg.Slug)
		}
	}
	payload, err := json.MarshalIndent(struct {
		Title      string   `json:"title"`
		Icon       string   `json:"icon"`
		PagesIndex string   `json:"pagesIndex"`
		Pages      []string `json:"pages"`
	}{
		Title:      "Go packages",
		Icon:       "Package",
		PagesIndex: "index",
		Pages:      pages,
	}, "", "  ")
	checkReference(err)
	return string(payload) + "\n"
}

func packageGroup(importPath string) string {
	relative := strings.TrimPrefix(importPath, modulePath+"/")
	switch {
	case importPath == modulePath:
		return "Entry point"
	case relative == "core" || strings.HasPrefix(relative, "core/"):
		return "Core runtime"
	case relative == "security" || strings.HasPrefix(relative, "security/"):
		return "Security"
	case relative == "protocol" || strings.HasPrefix(relative, "protocol/"):
		return "Protocols"
	case relative == "storage" || strings.HasPrefix(relative, "storage/"):
		return "Storage"
	case relative == "transport" || strings.HasPrefix(relative, "transport/"):
		return "Transports"
	case relative == "observability" || strings.HasPrefix(relative, "observability/"):
		return "Observability"
	case relative == "plugins" || strings.HasPrefix(relative, "plugins/"):
		return "Plugins"
	default:
		return "Utilities"
	}
}

func renderPackage(pkg documentedPackage) string {
	var output strings.Builder
	output.WriteString(fmt.Sprintf("---\ntitle: %q\n---\n\n", pkg.Info.ImportPath))
	output.WriteString("Exported server-side Go API for " + pkg.Info.ImportPath + ".\n\n")
	output.WriteString("- Import path: `" + pkg.Info.ImportPath + "`\n")
	output.WriteString("- Package name: `" + pkg.Info.Name + "`\n\n")
	if pkg.Doc.Doc != "" {
		output.WriteString(sanitizeMarkdown(strings.TrimSpace(pkg.Doc.Doc)) + "\n\n")
	}

	writeValues(&output, pkg.FileSet, "Constants", pkg.Doc.Consts)
	writeValues(&output, pkg.FileSet, "Variables", pkg.Doc.Vars)
	writeFunctions(&output, pkg.FileSet, "Functions", pkg.Doc.Funcs)

	if len(pkg.Doc.Types) != 0 {
		output.WriteString("## Types\n\n")
		for _, typ := range pkg.Doc.Types {
			output.WriteString("### `" + typ.Name + "`\n\n")
			writeDescription(&output, typ.Doc)
			writeGoDeclaration(&output, pkg.FileSet, typ.Decl)
			writeValues(&output, pkg.FileSet, "Constants associated with `"+typ.Name+"`", typ.Consts)
			writeValues(&output, pkg.FileSet, "Variables associated with `"+typ.Name+"`", typ.Vars)
			writeFunctions(&output, pkg.FileSet, "Constructors and functions for `"+typ.Name+"`", typ.Funcs)
			writeFunctions(&output, pkg.FileSet, "Methods on `"+typ.Name+"`", typ.Methods)
		}
	}

	if len(pkg.Doc.Consts) == 0 && len(pkg.Doc.Vars) == 0 && len(pkg.Doc.Funcs) == 0 && len(pkg.Doc.Types) == 0 {
		output.WriteString("This package exports no declarations; its package documentation defines the supported integration boundary.\n")
	}
	return output.String()
}

func writeValues(output *strings.Builder, fileSet *token.FileSet, title string, values []*doc.Value) {
	if len(values) == 0 {
		return
	}
	output.WriteString("## " + title + "\n\n")
	for _, value := range values {
		writeDescription(output, value.Doc)
		writeGoDeclaration(output, fileSet, value.Decl)
	}
}

func writeFunctions(output *strings.Builder, fileSet *token.FileSet, title string, functions []*doc.Func) {
	if len(functions) == 0 {
		return
	}
	output.WriteString("## " + title + "\n\n")
	for _, function := range functions {
		output.WriteString("### `" + function.Name + "`\n\n")
		writeDescription(output, function.Doc)
		declaration := *function.Decl
		declaration.Doc = nil
		declaration.Body = nil
		writeGoDeclaration(output, fileSet, &declaration)
	}
}

func writeDescription(output *strings.Builder, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	output.WriteString(sanitizeMarkdown(value) + "\n\n")
}

func writeGoDeclaration(output *strings.Builder, fileSet *token.FileSet, node ast.Node) {
	if node == nil {
		return
	}
	node = declarationWithoutTopLevelComments(node)
	var buffer bytes.Buffer
	config := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := config.Fprint(&buffer, fileSet, node); err != nil {
		panic(err)
	}
	output.WriteString("```go\n")
	output.WriteString(strings.TrimSpace(buffer.String()))
	output.WriteString("\n```\n\n")
}

func declarationWithoutTopLevelComments(node ast.Node) ast.Node {
	declaration, ok := node.(*ast.GenDecl)
	if !ok {
		return node
	}
	copyDeclaration := *declaration
	copyDeclaration.Doc = nil
	copyDeclaration.Specs = make([]ast.Spec, 0, len(declaration.Specs))
	for _, spec := range declaration.Specs {
		switch value := spec.(type) {
		case *ast.ValueSpec:
			copyValue := *value
			copyValue.Doc = nil
			copyValue.Comment = nil
			copyDeclaration.Specs = append(copyDeclaration.Specs, &copyValue)
		case *ast.TypeSpec:
			copyType := *value
			copyType.Doc = nil
			copyType.Comment = nil
			copyDeclaration.Specs = append(copyDeclaration.Specs, &copyType)
		default:
			copyDeclaration.Specs = append(copyDeclaration.Specs, spec)
		}
	}
	return &copyDeclaration
}

func sanitizeMarkdown(value string) string {
	value = replacePortTerminology(value)
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "{", "&#123;")
	value = strings.ReplaceAll(value, "}", "&#125;")
	return value
}

func replacePortTerminology(value string) string {
	replacer := strings.NewReplacer(
		"upstream implementation's CLI contract", "the schema migration contract",
		"environment, and so on", "environment, or explicit endpoint overrides",
		"behavior", "behavioral compatibility",
		"Behavior", "Compatibility",
	)
	return replacer.Replace(value)
}

func firstSentence(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return ""
	}
	if index := strings.Index(value, ". "); index >= 0 {
		return value[:index+1]
	}
	return value
}

func checkReference(err error) {
	if err != nil {
		panic(err)
	}
}
