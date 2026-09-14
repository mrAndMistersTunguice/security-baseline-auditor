// Package platformtest provides in-memory fakes of the platform interfaces
// for tests. Paths are compared in slash-separated, cleaned form so that
// Linux-style fixtures behave the same when tests run on Windows.
package platformtest

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// File is one fake filesystem entry.
type File struct {
	Data      []byte
	Mode      fs.FileMode // zero is a regular file with no permission bits
	UID, GID  int64
	IsSymlink bool
	// Err, when set, is returned by every operation on this path.
	Err error
}

// FS is an in-memory platform.FS.
type FS struct {
	files map[string]File
}

// NewFS returns an empty fake filesystem.
func NewFS() *FS {
	return &FS{files: make(map[string]File)}
}

func norm(name string) string {
	return filepath.ToSlash(filepath.Clean(name))
}

// Add registers a file and returns the FS for chaining.
func (f *FS) Add(name string, file File) *FS {
	f.files[norm(name)] = file
	return f
}

// AddText registers a regular 0644 root-owned file with the given content.
func (f *FS) AddText(name, content string) *FS {
	return f.Add(name, File{Data: []byte(content), Mode: 0o644})
}

// ReadFile implements platform.FS.
func (f *FS) ReadFile(name string, maxBytes int64) ([]byte, error) {
	file, ok := f.files[norm(name)]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if file.Err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: file.Err}
	}
	if !file.Mode.IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: name, Err: platform.ErrNotRegular}
	}
	if int64(len(file.Data)) > maxBytes {
		return nil, &fs.PathError{Op: "read", Path: name, Err: platform.ErrTooLarge}
	}
	return slices.Clone(file.Data), nil
}

// Stat implements platform.FS.
func (f *FS) Stat(name string) (platform.FileInfo, error) {
	file, ok := f.files[norm(name)]
	if !ok {
		return platform.FileInfo{}, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrNotExist}
	}
	if file.Err != nil {
		return platform.FileInfo{}, &fs.PathError{Op: "lstat", Path: name, Err: file.Err}
	}
	return platform.FileInfo{Mode: file.Mode, IsSymlink: file.IsSymlink, UID: file.UID, GID: file.GID}, nil
}

// Glob implements platform.FS using path.Match semantics.
func (f *FS) Glob(pattern string) ([]string, error) {
	pattern = norm(pattern)
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	var out []string
	for name := range f.files {
		if ok, _ := path.Match(pattern, name); ok {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ReadDirNames implements platform.FS. Directories are implicit.
func (f *FS) ReadDirNames(name string) ([]string, error) {
	prefix := strings.TrimSuffix(norm(name), "/") + "/"
	seen := map[string]bool{}
	for p := range f.files {
		if rest, ok := strings.CutPrefix(p, prefix); ok && rest != "" {
			child, _, _ := strings.Cut(rest, "/")
			seen[child] = true
		}
	}
	if len(seen) == 0 {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}

// Runner is a fake platform.Runner keyed by the full command line.
type Runner struct {
	Outputs map[string]Output
	Calls   []string
}

// Output is the canned result of one command.
type Output struct {
	Stdout []byte
	Err    error
}

// Run implements platform.Runner.
func (r *Runner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{path}, args...), " ")
	r.Calls = append(r.Calls, key)
	out, ok := r.Outputs[key]
	if !ok {
		return nil, fmt.Errorf("fake runner: unexpected command %q: %w", key, fs.ErrNotExist)
	}
	return out.Stdout, out.Err
}
