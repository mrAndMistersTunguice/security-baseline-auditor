//go:build unix

package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

// checkTrustedBinary refuses to run a program unless the program and every
// directory on its resolved path are owned by root and not writable by group
// or others. This prevents a local user who can write to the binary (or
// swap it through a writable parent directory) from getting code executed by
// an auditor running as root.
//
// It returns the fully resolved path, which is what must be executed:
// executing the original path would re-resolve symlinks that may live in
// directories outside the checked chain.
func checkTrustedBinary(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file", ErrUntrustedBinary, resolved)
	}
	for p := resolved; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if uid, _ := ownership(fi); uid != 0 {
			return "", fmt.Errorf("%w: %s is not owned by root", ErrUntrustedBinary, p)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("%w: %s is writable by group or others", ErrUntrustedBinary, p)
		}
		if filepath.Dir(p) == p {
			return resolved, nil
		}
	}
}
