//go:build !windows

package collector

import (
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// collectWindows is only reachable when a test sets env.GOOS to "windows"
// on another OS; the Windows collectors need the Windows API.
func collectWindows(_ platform.Env, snap *model.Snapshot) {
	const why = "Windows collectors are only available in Windows builds"
	snap.Accounts = model.Unavailable[model.Accounts](model.Unsupported, why)
	snap.SSHD = model.Unavailable[model.SSHDConfig](model.Unsupported, why)
	snap.Firewall = model.Unavailable[model.Firewall](model.Unsupported, why)
	snap.Files = model.Unavailable[[]model.FileEntry](model.Unsupported, why)
}
