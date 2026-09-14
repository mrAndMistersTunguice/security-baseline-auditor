//go:build !unix

package platform

import "fmt"

// checkTrustedBinary: no collector executes programs on non-Unix platforms,
// and without an ACL check there is no sound trust decision, so execution
// is refused.
func checkTrustedBinary(path string) (string, error) {
	return "", fmt.Errorf("%w: command execution is not supported on this platform (%s)", ErrUntrustedBinary, path)
}
