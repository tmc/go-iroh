// Command qngregen regenerates internal/qng from the quic-go module pinned in
// go.mod.
//
// The fork is not a pristine copy of quic-go: go-iroh modifies vendored files
// in place and adds files of its own. Regenerating over that tree would discard
// those edits, so regeneration refuses to run unless the tree still matches the
// pinned upstream release. To take a new upstream release, generate a pristine
// tree with -o and merge it; see internal/qng/README.md.
//
// Usage:
//
//	qngregen           regenerate internal/qng in place (refuses if edited)
//	qngregen -o dir    write a pristine forked tree to dir
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	modulePath = "github.com/quic-go/quic-go"
	destDir    = "internal/qng"
)

var importRewrites = []struct {
	old string
	new string
}{
	{modulePath + "/internal/", "github.com/tmc/go-iroh/internal/qng/internal/"},
	{modulePath + "/qlogwriter/", "github.com/tmc/go-iroh/internal/qng/qlogwriter/"},
	{modulePath + "/qlogwriter", "github.com/tmc/go-iroh/internal/qng/qlogwriter"},
	{modulePath + "/qlog", "github.com/tmc/go-iroh/internal/qng/qlog"},
	{modulePath + "/quicvarint", "github.com/tmc/go-iroh/internal/qng/quicvarint"},
	{modulePath, "github.com/tmc/go-iroh/internal/qng"},
	{"crypto/tls", "github.com/tmc/go-iroh/internal/itls/tls"},
}

var outDir = flag.String("o", "", "write a pristine forked tree to `dir` instead of regenerating in place")

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "qngregen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	if err := os.Chdir(root); err != nil {
		return err
	}
	if *outDir != "" {
		if err := generate(*outDir); err != nil {
			return err
		}
		fmt.Printf("wrote pristine tree to %s\n", *outDir)
		return nil
	}

	tmp, err := os.MkdirTemp("", "qngregen-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	base := filepath.Join(tmp, "base")
	if err := generate(base); err != nil {
		return err
	}
	delta, err := compare(base, destDir)
	if err != nil {
		return err
	}
	if !delta.empty() {
		return fmt.Errorf("%s carries local edits (%s); regenerating would discard them.\n"+
			"To take a new upstream release, generate a pristine tree with -o and merge it.\n"+
			"See %s/README.md", destDir, delta.summary(), destDir)
	}
	if err := replaceTree(destDir, base); err != nil {
		return err
	}
	fmt.Println("done; now run: go build ./... && go test ./internal/qng/")
	return nil
}

// generate writes a pristine forked copy of the pinned quic-go release to dir:
// every non-test Go file of the module, with its imports rewritten. It carries
// none of go-iroh's own files or edits.
func generate(dir string) error {
	modDir, err := moduleDir(modulePath)
	if err != nil {
		return err
	}
	pkgs, err := quicGoPackages()
	if err != nil {
		return err
	}
	fmt.Printf("forking quic-go from: %s\n", modDir)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	count := 0
	for _, pkg := range pkgs {
		rel := strings.TrimPrefix(strings.TrimPrefix(pkg, modulePath), "/")
		src, dst := filepath.Join(modDir, rel), filepath.Join(dir, rel)
		if rel == "" {
			src, dst = modDir, dir
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		files, err := filepath.Glob(filepath.Join(src, "*.go"))
		if err != nil {
			return err
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			if err := copyFile(file, filepath.Join(dst, filepath.Base(file))); err != nil {
				return err
			}
			count++
		}
	}
	fmt.Printf("copied %d files\n", count)

	if err := rewriteGoFiles(dir); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(modDir, "LICENSE"), filepath.Join(dir, "LICENSE")); err != nil {
		return err
	}
	return gofmt(dir)
}

// A delta describes how a fork tree differs from the pristine tree it was
// generated from. Test files are counted separately: regeneration never copies
// upstream tests, so every test file in the fork is go-iroh's own.
type delta struct {
	modified []string
	added    []string
	tests    []string
	removed  []string
}

func (d *delta) empty() bool {
	return len(d.modified) == 0 && len(d.added) == 0 && len(d.tests) == 0 && len(d.removed) == 0
}

func (d *delta) summary() string {
	return fmt.Sprintf("%d modified, %d added, %d test files, %d removed",
		len(d.modified), len(d.added), len(d.tests), len(d.removed))
}

// compare reports how the tree at fork differs from the pristine tree at base.
func compare(base, fork string) (*delta, error) {
	baseFiles, err := treeFiles(base)
	if err != nil {
		return nil, err
	}
	forkFiles, err := treeFiles(fork)
	if err != nil {
		return nil, err
	}
	d := new(delta)
	for _, rel := range forkFiles {
		switch {
		case !contains(baseFiles, rel):
			if strings.HasSuffix(rel, "_test.go") {
				d.tests = append(d.tests, rel)
			} else {
				d.added = append(d.added, rel)
			}
		default:
			same, err := sameFile(filepath.Join(base, rel), filepath.Join(fork, rel))
			if err != nil {
				return nil, err
			}
			if !same {
				d.modified = append(d.modified, rel)
			}
		}
	}
	for _, rel := range baseFiles {
		if !contains(forkFiles, rel) {
			d.removed = append(d.removed, rel)
		}
	}
	return d, nil
}

// treeFiles lists the files under dir, as slash-separated paths relative to it,
// sorted. Version control metadata is skipped.
func treeFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if e.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func contains(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}

func sameFile(a, b string) (bool, error) {
	x, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	y, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(x, y), nil
}

// replaceTree replaces dst with src, leaving dst untouched if the move fails.
func replaceTree(dst, src string) error {
	old := dst + ".old"
	if err := os.RemoveAll(old); err != nil {
		return err
	}
	if err := os.Rename(dst, old); err != nil {
		return err
	}
	if err := copyTree(src, dst); err != nil {
		os.RemoveAll(dst)
		os.Rename(old, dst)
		return err
	}
	return os.RemoveAll(old)
}

func moduleRoot() (string, error) {
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("not in a Go module")
	}
	return filepath.Dir(gomod), nil
}

func moduleDir(path string) (string, error) {
	cmd := exec.Command("go", "list", "-m", "-json", path)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list -m %s: %w", path, err)
	}
	var m struct {
		Dir string
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "", err
	}
	if m.Dir == "" {
		return "", fmt.Errorf("module %s has no local directory; run go mod download %s", path, path)
	}
	return m.Dir, nil
}

func quicGoPackages() ([]string, error) {
	cmd := exec.Command("go", "list", "-deps", modulePath)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -deps %s: %w", modulePath, err)
	}
	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		if line == modulePath || strings.HasPrefix(line, modulePath+"/") {
			pkgs = append(pkgs, line)
		}
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst)
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		return copyFile(path, out)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func rewriteGoFiles(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		return rewriteImports(path)
	})
}

func rewriteImports(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return err
	}
	changed := false
	for _, spec := range file.Imports {
		old, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		newPath, ok := rewriteImportPath(old)
		if !ok {
			continue
		}
		if old == "crypto/tls" && spec.Name == nil {
			spec.Name = ast.NewIdent("tls")
		}
		spec.Path.Value = strconv.Quote(newPath)
		changed = true
	}
	if !changed {
		return nil
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, file); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func rewriteImportPath(path string) (string, bool) {
	for _, r := range importRewrites {
		if path == r.old {
			return r.new, true
		}
		if strings.HasSuffix(r.old, "/") && strings.HasPrefix(path, r.old) {
			return r.new + strings.TrimPrefix(path, r.old), true
		}
	}
	return path, false
}

func gofmt(path string) error {
	cmd := exec.Command("gofmt", "-w", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gofmt %s: %w", path, err)
	}
	return nil
}
