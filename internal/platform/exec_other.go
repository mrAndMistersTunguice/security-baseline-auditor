//go:build !unix

package platform

import (
	"context"
	"fmt"
)

// Run implements Runner. No collector executes programs on non-Unix
// platforms, and without an ACL-based trust check there is no sound way to
// decide whether a binary is safe to run, so execution is always refused.
func (ExecRunner) Run(_ context.Context, path string, _ ...string) ([]byte, error) {
	return nil, fmt.Errorf("run %q: %w: command execution is not supported on this platform", path, ErrUntrustedBinary)
}
