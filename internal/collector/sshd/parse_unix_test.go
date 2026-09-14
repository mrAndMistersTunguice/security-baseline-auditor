//go:build unix

package sshd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// TestUnreadableDropInDirectoryOnRealFS verifies with the real filesystem
// that filepath.Glob's silent handling of unreadable directories does not
// produce an incomplete configuration.
func TestUnreadableDropInDirectoryOnRealFS(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	dropins := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(dropins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropins, "00-root.conf"), []byte("PermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Include sshd_config.d/*.conf\nPermitRootLogin no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dropins, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dropins, 0o755) })

	sec := Collect(platform.OSFS{}, []Location{{MainFile: filepath.Join(dir, "sshd_config"), ConfigDir: dir}})
	if sec.Status != model.PermissionDenied {
		t.Fatalf("status = %s (%s), want permission_denied", sec.Status, sec.Detail)
	}
}
