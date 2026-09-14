//go:build windows

package collector

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/firewall"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/hostinfo"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/sshd"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

func collectWindows(env platform.Env, snap *model.Snapshot) {
	hostinfo.CollectWindows(&snap.Host)

	snap.Accounts = model.Unavailable[model.Accounts](model.Unsupported,
		"local account collection is not implemented on Windows")
	snap.Files = model.Unavailable[[]model.FileEntry](model.Unsupported,
		"file permission checks require ACL inspection, which is not implemented on Windows")
	snap.Firewall = firewall.CollectWindows()

	// Win32-OpenSSH keeps its configuration in %ProgramData%\ssh. The
	// known-folder API is used instead of the environment variable, which
	// the invoking user controls.
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		snap.SSHD = model.Unavailable[model.SSHDConfig](model.Failed, "cannot resolve ProgramData folder: "+err.Error())
		return
	}
	dir := filepath.Join(programData, "ssh")
	snap.SSHD = sshd.Collect(env.FS, []sshd.Location{{MainFile: filepath.Join(dir, "sshd_config"), ConfigDir: dir}})
}
