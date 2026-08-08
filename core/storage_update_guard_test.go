package core

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoConsumerUsesUpdateAsMultiClauseCompareAndSwap(t *testing.T) {
	set := token.NewFileSet()
	var offenders []string
	repositoryRoot := ".."
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			relative, relativeErr := filepath.Rel(repositoryRoot, path)
			if relativeErr != nil {
				return relativeErr
			}
			clean := filepath.ToSlash(relative)
			if clean == ".git" || clean == "storage/adaptertest" ||
				clean == "better-auth-main" || entry.Name() == "node_modules" ||
				entry.Name() == ".next" || entry.Name() == ".source" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || !isStorageUpdateParams(literal.Type) {
				return true
			}
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				name, nameOK := field.Key.(*ast.Ident)
				if !nameOK || name.Name != "Where" {
					continue
				}
				clauses, ok := field.Value.(*ast.CompositeLit)
				if ok && len(clauses.Elts) > 1 {
					position := set.Position(field.Pos())
					offenders = append(offenders, fmt.Sprintf("%s:%d (%d clauses)", path, position.Line, len(clauses.Elts)))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("multi-clause Adapter.Update is a non-portable compare-and-swap; use IncrementOne or ConsumeOne:\n%s", strings.Join(offenders, "\n"))
	}
}

func isStorageUpdateParams(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "UpdateParams"
}
