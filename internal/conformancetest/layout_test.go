package conformancetest

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestRepositoryKeepsThinRootFacade(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve layout test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read repository root: %v", err)
	}

	var goFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			goFiles = append(goFiles, entry.Name())
		}
	}
	slices.Sort(goFiles)
	wantGoFiles := []string{"doc.go", "facade_gen.go", "public_types_compile_test.go"}
	if !slices.Equal(goFiles, wantGoFiles) {
		t.Fatalf("root package must stay a generated facade: got %v, want %v", goFiles, wantGoFiles)
	}

	for _, family := range []string{"core", "observability", "protocol", "security", "storage", "transport"} {
		assertDirectory(t, filepath.Join(root, family))
	}
	for _, legacy := range []string{
		"authorization",
		"contract",
		"cookies",
		"crypto",
		"engine",
		"instrumentation",
		"logger",
		"model",
		"oauth2",
		"providers",
		"ratelimit",
		"saml",
		"secondary",
		"telemetry",
		"webauthn",
	} {
		if _, err := os.Stat(filepath.Join(root, legacy)); !os.IsNotExist(err) {
			t.Fatalf("legacy top-level package %q returned; keep it inside its domain family", legacy)
		}
	}
}

func assertDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat required package family %s: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("required package family %s is not a directory", path)
	}
}
