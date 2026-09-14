// Package platform isolates every direct interaction with the operating
// system (file access, process execution, privilege detection) behind small
// interfaces so that collectors can be tested with fakes on any OS.
package platform

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
)

var (
	// ErrNotRegular is returned when a path that must be a regular file is
	// a directory, device, FIFO or socket.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge is returned when a file or command output exceeds the
	// configured size limit.
	ErrTooLarge = errors.New("size limit exceeded")
	// ErrUntrustedBinary is returned when an executable does not satisfy the
	// ownership and permission requirements for being run by the auditor.
	ErrUntrustedBinary = errors.New("refusing to execute untrusted binary")
)

// FileInfo is the subset of file metadata the auditor needs.
type FileInfo struct {
	// Mode of the file. If the path is a symlink, Mode describes the target.
	Mode fs.FileMode
	// IsSymlink reports whether the path itself is a symbolic link.
	IsSymlink bool
	// UID and GID of the file (target, for symlinks); -1 when the platform
	// does not expose numeric ownership.
	UID, GID int64
}

// FS is read-only filesystem access.
type FS interface {
	// ReadFile reads a regular file (following symlinks), failing with
	// ErrNotRegular for other file types and ErrTooLarge when the file is
	// larger than maxBytes. It never blocks on FIFOs.
	ReadFile(name string, maxBytes int64) ([]byte, error)
	// Stat returns metadata for name; symlinks are reported and followed.
	Stat(name string) (FileInfo, error)
	// Glob returns the names matching pattern in lexical order.
	Glob(pattern string) ([]string, error)
	// ReadDirNames returns the names of the entries of a directory.
	ReadDirNames(name string) ([]string, error)
}

// Runner executes external programs. Implementations must not invoke a shell.
type Runner interface {
	// Run executes the program at the absolute path with args and returns
	// its standard output.
	Run(ctx context.Context, path string, args ...string) ([]byte, error)
}

// Env bundles the platform services used by collectors.
type Env struct {
	GOOS     string
	FS       FS
	Runner   Runner
	Elevated bool
}

// Host returns the Env for the machine the auditor is running on.
func Host() Env {
	return Env{
		GOOS:     runtime.GOOS,
		FS:       OSFS{},
		Runner:   ExecRunner{},
		Elevated: isElevated(),
	}
}

// IsPermission reports whether err is a permission error.
func IsPermission(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}

// IsNotExist reports whether err indicates a missing file.
func IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
