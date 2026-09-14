//go:build unix

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("run %q: program path must be absolute", path)
	}
	resolved, err := checkTrustedBinary(path)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolved, args...)
	// Do not inherit the caller's environment: variables such as
	// LD_PRELOAD or a manipulated PATH must not influence a program the
	// auditor may run as root. LC_ALL=C keeps output unlocalized.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	stdout := &limitedBuffer{limit: MaxCommandOutput}
	stderr := &limitedBuffer{limit: maxCommandStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Ensure Wait returns even if a child process keeps the pipes open.
	cmd.WaitDelay = 2 * time.Second

	err = cmd.Run()
	if stdout.overflow {
		return nil, fmt.Errorf("run %s: output %w (%d bytes)", path, ErrTooLarge, MaxCommandOutput)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("run %s: %w", path, ctxErr)
		}
		msg := strings.TrimSpace(stderr.String())
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && msg != "" {
			return nil, fmt.Errorf("run %s: %w: %s", path, err, firstLine(msg))
		}
		return nil, fmt.Errorf("run %s: %w", path, err)
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return s
}

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
