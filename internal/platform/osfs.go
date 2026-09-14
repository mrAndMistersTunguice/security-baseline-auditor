package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// OSFS implements FS on top of the real filesystem.
type OSFS struct{}

// ReadFile implements FS.
func (OSFS) ReadFile(name string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("read %s: invalid size limit %d", name, maxBytes)
	}
	f, err := openNoBlock(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Check the type of the opened file, not of the path, so that a file
	// swapped between a stat and the open cannot bypass the check.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &os.PathError{Op: "read", Path: name, Err: ErrNotRegular}
	}

	// Do not trust info.Size(): procfs files report 0 and files may grow.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &os.PathError{Op: "read", Path: name, Err: fmt.Errorf("%w: larger than %d bytes", ErrTooLarge, maxBytes)}
	}
	return data, nil
}

// Stat implements FS.
func (OSFS) Stat(name string) (FileInfo, error) {
	linfo, err := os.Lstat(name)
	if err != nil {
		return FileInfo{}, err
	}
	info := linfo
	isLink := linfo.Mode()&os.ModeSymlink != 0
	if isLink {
		if info, err = os.Stat(name); err != nil {
			return FileInfo{}, err
		}
	}
	uid, gid := ownership(info)
	return FileInfo{Mode: info.Mode(), IsSymlink: isLink, UID: uid, GID: gid}, nil
}

// Glob implements FS.
func (OSFS) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

// ReadDirNames implements FS.
func (OSFS) ReadDirNames(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}
