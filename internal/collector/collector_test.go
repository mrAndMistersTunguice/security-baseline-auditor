package collector

import (
	"context"
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func linuxFS() *platformtest.FS {
	return platformtest.NewFS().
		AddText("/etc/os-release", "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n").
		AddText("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n").
		Add("/etc/shadow", platformtest.File{Mode: 0o640, Err: fs.ErrPermission}).
		AddText("/etc/ssh/sshd_config", "PermitRootLogin no\n").
		AddText("/proc/1/comm", "systemd\n")
}

func TestCollectLinuxUnprivileged(t *testing.T) {
	runner := &platformtest.Runner{}
	snap := Collect(context.Background(), platform.Env{GOOS: "linux", FS: linuxFS(), Runner: runner})

	if snap.Host.DistroID != "debian" || snap.Host.Elevated {
		t.Errorf("host = %+v", snap.Host)
	}
	checks := map[string]model.CollectionStatus{
		"accounts": snap.Accounts.Status,
		"shadow":   snap.Accounts.Data.Shadow.Status,
		"sshd":     snap.SSHD.Status,
		"firewall": snap.Firewall.Status,
		"files":    snap.Files.Status,
	}
	want := map[string]model.CollectionStatus{
		"accounts": model.Collected,
		"shadow":   model.PermissionDenied,
		"sshd":     model.Collected,
		"firewall": model.Collected,
		"files":    model.Collected,
	}
	for k, got := range checks {
		if got != want[k] {
			t.Errorf("%s status = %s, want %s", k, got, want[k])
		}
	}
	if len(runner.Calls) != 0 {
		t.Errorf("unprivileged Linux collection executed %q", runner.Calls)
	}

	// The snapshot must round-trip through JSON (it is exposed by
	// `sba snapshot`).
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var back model.Snapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.SSHD.Status != model.Collected || len(back.SSHD.Data.Directives) != 1 {
		t.Errorf("round-trip lost data: %+v", back.SSHD)
	}
}

func TestCollectUnknownUnixMarksUnsupported(t *testing.T) {
	snap := Collect(context.Background(), platform.Env{GOOS: "freebsd", FS: linuxFS(), Runner: &platformtest.Runner{}})
	for name, st := range map[string]model.CollectionStatus{
		"accounts": snap.Accounts.Status,
		"firewall": snap.Firewall.Status,
		"files":    snap.Files.Status,
	} {
		if st != model.Unsupported {
			t.Errorf("%s = %s, want unsupported", name, st)
		}
	}
	if snap.SSHD.Status != model.Collected {
		t.Errorf("portable sshd parser should run: %s", snap.SSHD.Status)
	}
}
