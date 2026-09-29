// Package dialsites verifies that every call in this module that dials a
// remote endpoint appears in a checked-in list.
//
// Tests and benchmarks must not reach the public relay servers. Network
// isolation on the test host is what enforces that; this test catches a new
// dial site landing unnoticed.
package dialsites

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// dialMethods are the method names this module uses to reach a remote
// endpoint. The check matches the method name alone: the calls are methods
// on values, such as tr.Dial and e.transport.Dial, which a match on pkg.Func
// would miss.
var dialMethods = []string{"Dial", "DialAddr", "DialAddrEarly", "DialContext"}

// sites lists the known dial calls, keyed by file and method name, with the
// reason each may reach the network. Calls to the same method in one file
// share an entry.
var sites = map[string]string{
	"internal/relayclient/client.go:Dial":        "relay WebSocket; the endpoint comes from the caller's relay map",
	"internal/relayclient/client.go:DialContext": "HTTP client beneath the WebSocket dial above",
	"internal/relayclient/proxy.go:DialContext":  "configured proxy for a caller-selected relay",
	"internal/netreport/qad.go:Dial":             "QUIC address discovery against a relay",
	"iroh/endpoint.go:Dial":                      "QUIC address discovery from the endpoint",
	"internal/qng/client.go:Dial":                "transport primitive beneath the callers above",
	"internal/portmapper/natpmp.go:DialContext":  "local gateway, not relay infrastructure",
	"relay/nearest.go:DialContext":               "latency probe; callers supply the endpoint set",
	"internal/itls/tls/tls.go:DialContext":       "vendored crypto/tls; generic primitive",
}

func TestDialSitesAreListed(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()

	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "testdata" || n == "vendor" {
				return filepath.SkipDir
			}
			// A directory holding its own .git is a nested checkout, such as
			// a linked worktree or a vendored clone, not this module's
			// source. The entry is a directory in a clone and a file in a
			// linked worktree, so match either.
			if path != root {
				if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// Fail on a parse error; a skipped file is an unchecked file.
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !slices.Contains(dialMethods, sel.Sel.Name) {
				return true
			}
			key := rel + ":" + sel.Sel.Name
			found[key] = true
			if _, ok := sites[key]; !ok {
				t.Errorf("unlisted dial site: %s at %s\n"+
					"\tAdd it to sites with the reason it may reach the network.",
					key, fset.Position(call.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking module: %v", err)
	}

	// Without these, a walk that matched nothing would report a clean module.
	if len(found) == 0 {
		t.Fatal("no dial sites found; the walk inspected nothing")
	}
	for key := range sites {
		if !found[key] {
			t.Errorf("sites lists %s, which no longer exists; remove it", key)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}
