package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// MaxCommandOutput caps the standard output captured from a command.
	MaxCommandOutput = 16 << 20
	maxCommandStderr = 64 << 10
	// DefaultCommandTimeout bounds a single command when the caller's
	// context has no earlier deadline.
	DefaultCommandTimeout = 15 * time.Second
)

// ExecRunner runs programs directly via execve (never through a shell), with
// a fixed minimal environment, a timeout and bounded output.
type ExecRunner struct{}

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

// limitedBuffer stores up to limit bytes and records whether more were
// written. It never returns an error so the child process is not killed by
// SIGPIPE; the overflow flag is checked after the command exits.
type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.Len(); remaining < len(p) {
		b.overflow = true
		if remaining > 0 {
			b.Buffer.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}
