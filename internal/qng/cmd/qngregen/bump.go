package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// bumpTo takes a new upstream release. It generates the pristine tree for the
// currently pinned release and for the new one, then merges the difference
// between them into internal/qng, which carries the fork's own edits.
//
// The merge is per file and three-way, so a file the fork has not touched is
// taken whole, and a file it has touched keeps its edits unless upstream
// changed the same lines. Conflicts are left in the tree with markers, for the
// same reason git leaves them there: resolving them needs a person.
func bumpTo(version string) error {
	current, err := moduleVersion(modulePath)
	if err != nil {
		return err
	}
	if version == current {
		return fmt.Errorf("%s is already pinned at %s", destDir, current)
	}

	tmp, err := os.MkdirTemp("", "qngregen-bump-*")
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
	if delta.empty() {
		return fmt.Errorf("%s matches pristine %s; regenerate with -o instead", destDir, current)
	}
	fmt.Fprintf(os.Stderr, "fork at %s: %s\n", current, delta.summary())

	if err := goGet(modulePath + "@" + version); err != nil {
		return err
	}
	theirs := filepath.Join(tmp, "theirs")
	if err := generate(theirs); err != nil {
		return err
	}

	res, err := merge(destDir, base, theirs)
	if err != nil {
		return err
	}
	if err := recordVersion(version); err != nil {
		return err
	}
	res.report(os.Stderr, current, version)
	if len(res.conflicted) > 0 {
		return fmt.Errorf("%d files conflict; resolve them, then run: go build ./... && go test %s/...",
			len(res.conflicted), destDir)
	}
	fmt.Fprintf(os.Stderr, "now run: go build ./... && go test %s/...\n", destDir)
	return nil
}

// recordVersion updates the release named at the end of the README, which is
// the only place the fork's provenance is written down for a reader.
func recordVersion(version string) error {
	path := filepath.Join(destDir, "README.md")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	i := strings.LastIndex(string(b), "quic-go **")
	if i < 0 {
		return fmt.Errorf("%s: no version line to update", path)
	}
	j := strings.Index(string(b[i:]), "\n")
	if j < 0 {
		j = len(b) - i
	}
	updated := string(b[:i]) + "quic-go **" + version + "**." + string(b[i+j:])
	return os.WriteFile(path, []byte(updated), 0o644)
}

// A mergeResult records what taking a release did to each file.
type mergeResult struct {
	taken      []string // fork had not touched it: replaced with upstream's
	merged     []string // fork edits and upstream changes combined cleanly
	conflicted []string // both changed the same lines; markers left in the file
	added      []string // new upstream file
	removed    []string // upstream dropped it, and the fork had not touched it
	orphaned   []string // upstream dropped a file the fork had edited
	dropped    []string // upstream changed a file the fork does not carry
}

func (r *mergeResult) report(w io.Writer, from, to string) {
	fmt.Fprintf(w, "\n%s %s -> %s: %d taken, %d merged, %d conflicted, %d added, %d removed\n\n",
		modulePath, from, to, len(r.taken), len(r.merged), len(r.conflicted), len(r.added), len(r.removed))
	section := func(name string, files []string) {
		if len(files) == 0 {
			return
		}
		fmt.Fprintf(w, "%s (%d):\n", name, len(files))
		for _, f := range slices.Sorted(slices.Values(files)) {
			fmt.Fprintf(w, "\t%s\n", f)
		}
		fmt.Fprintln(w)
	}
	section("conflicted", r.conflicted)
	section("merged", r.merged)
	section("added", r.added)
	section("removed", r.removed)
	section("upstream removed, fork had edited", r.orphaned)
	section("upstream changed, fork does not carry", r.dropped)
}

// merge applies the difference between the base and theirs trees to fork.
func merge(fork, base, theirs string) (*mergeResult, error) {
	baseFiles, err := treeFiles(base)
	if err != nil {
		return nil, err
	}
	theirFiles, err := treeFiles(theirs)
	if err != nil {
		return nil, err
	}
	res := new(mergeResult)
	for _, rel := range union(baseFiles, theirFiles) {
		inBase := contains(baseFiles, rel)
		inTheirs := contains(theirFiles, rel)
		basePath := filepath.Join(base, filepath.FromSlash(rel))
		theirPath := filepath.Join(theirs, filepath.FromSlash(rel))
		forkPath := filepath.Join(fork, filepath.FromSlash(rel))
		inFork, err := exists(forkPath)
		if err != nil {
			return nil, err
		}

		switch {
		case inBase && inTheirs:
			same, err := sameFile(basePath, theirPath)
			if err != nil {
				return nil, err
			}
			if same {
				continue // upstream did not touch it
			}
			if !inFork {
				res.dropped = append(res.dropped, rel)
				continue
			}
			untouched, err := sameFile(basePath, forkPath)
			if err != nil {
				return nil, err
			}
			if untouched {
				if err := copyFile(theirPath, forkPath); err != nil {
					return nil, err
				}
				res.taken = append(res.taken, rel)
				continue
			}
			conflicts, err := mergeFile(forkPath, basePath, theirPath)
			if err != nil {
				return nil, err
			}
			if conflicts {
				res.conflicted = append(res.conflicted, rel)
			} else {
				res.merged = append(res.merged, rel)
			}

		case inTheirs: // upstream added it
			if inFork {
				// The fork added a file of the same name. Merging against an
				// empty base keeps both sides' lines and marks the overlap.
				empty := filepath.Join(base, ".empty")
				if err := os.WriteFile(empty, nil, 0o644); err != nil {
					return nil, err
				}
				conflicts, err := mergeFile(forkPath, empty, theirPath)
				if err != nil {
					return nil, err
				}
				if conflicts {
					res.conflicted = append(res.conflicted, rel)
				} else {
					res.merged = append(res.merged, rel)
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(forkPath), 0o755); err != nil {
				return nil, err
			}
			if err := copyFile(theirPath, forkPath); err != nil {
				return nil, err
			}
			res.added = append(res.added, rel)

		default: // upstream removed it
			if !inFork {
				continue
			}
			untouched, err := sameFile(basePath, forkPath)
			if err != nil {
				return nil, err
			}
			if !untouched {
				res.orphaned = append(res.orphaned, rel)
				continue
			}
			if err := os.Remove(forkPath); err != nil {
				return nil, err
			}
			res.removed = append(res.removed, rel)
		}
	}
	return res, nil
}

// mergeFile merges the changes from base to theirs into fork, in place, and
// reports whether it left conflict markers.
func mergeFile(fork, base, theirs string) (bool, error) {
	cmd := exec.Command("git", "merge-file", "--diff3",
		"-L", "go-iroh", "-L", "quic-go (pinned)", "-L", "quic-go (new)",
		fork, base, theirs)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return false, nil
	}
	// git merge-file exits with the number of conflicts, and with a negative
	// value, reported as 255, for an error.
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() > 0 && exit.ExitCode() < 128 {
		return true, nil
	}
	return false, fmt.Errorf("git merge-file %s: %w", fork, err)
}

func goGet(target string) error {
	fmt.Fprintf(os.Stderr, "go get %s\n", target)
	cmd := exec.Command("go", "get", target)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go get %s: %w", target, err)
	}
	return nil
}

func moduleVersion(path string) (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}}", path)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list -m %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// union returns the sorted union of two sorted lists.
func union(a, b []string) []string {
	all := slices.Concat(a, b)
	slices.Sort(all)
	return slices.Compact(all)
}
