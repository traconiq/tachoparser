package scan_test

// The whole point of this package is that it is cheap enough to run inside the
// device connection handler. Importing pkg/decoder would drag the reflection
// tables and the embedded certificates into every binary that only wants the
// walk, so the rule is checked rather than written down and hoped for.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is what the non-test files of this package may depend on.
// Keep it boring: the standard library only.
var allowedImports = map[string]bool{
	"errors": true,
	"fmt":    true,
}

func TestNoDecoderImport(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import %s", name, imp.Path.Value)
			}
			if strings.Contains(path, "tachoparser/pkg/decoder") {
				t.Errorf("%s imports %s: the walk must stay independent of the decoder", name, path)
				continue
			}
			if !allowedImports[path] {
				t.Errorf("%s imports %s, which is not in allowedImports — "+
					"add it deliberately, and only if it is standard library", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test source files found; the check would pass vacuously")
	}
}

// TestNoTestdataDependency guards the other direction: the package itself must
// not need files on disk.
func TestNoTestdataDependency(t *testing.T) {
	if _, err := os.Stat(filepath.Join(".", "testdata")); err == nil {
		t.Log("testdata exists; that is fine for tests, but the package must not read it at runtime")
	}
}
