// Package collector builds a model.Snapshot of the local system. It only
// gathers data; it makes no security judgements.
package collector

import (
	"context"
	"runtime"
	"time"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/accounts"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/files"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/firewall"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/hostinfo"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/sshd"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// Collect gathers a snapshot for env.GOOS. Sections without an
// implementation for the platform are marked model.Unsupported, never left
// looking like empty-but-collected data.
//
// Collection is sequential: it is fast (a handful of small files and at most
// one external command), and sequential code keeps ordering deterministic.
func Collect(ctx context.Context, env platform.Env) *model.Snapshot {
	snap := &model.Snapshot{
		SchemaVersion: model.SnapshotSchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Host: model.Host{
			OS:       env.GOOS,
			Arch:     runtime.GOARCH,
			Hostname: hostinfo.Hostname(),
			Elevated: env.Elevated,
		},
	}

	switch env.GOOS {
	case "linux":
		collectLinux(ctx, env, snap)
	case "windows":
		collectWindows(env, snap)
	default:
		collectOtherUnix(env, snap)
	}
	return snap
}

func collectLinux(ctx context.Context, env platform.Env, snap *model.Snapshot) {
	hostinfo.CollectUnix(env.FS, &snap.Host)
	snap.Accounts = accounts.Collect(env.FS)
	snap.SSHD = sshd.Collect(env.FS, sshd.UnixLocations)
	snap.Firewall = firewall.CollectLinux(ctx, env)
	snap.Files = files.Collect(env.FS, files.LinuxPaths)
}

// collectOtherUnix covers platforms without a dedicated implementation
// (macOS, BSDs). Only the portable sshd_config parser runs there.
func collectOtherUnix(env platform.Env, snap *model.Snapshot) {
	const why = "not implemented for this operating system"
	snap.Accounts = model.Unavailable[model.Accounts](model.Unsupported, why)
	snap.SSHD = sshd.Collect(env.FS, sshd.UnixLocations)
	snap.Firewall = model.Unavailable[model.Firewall](model.Unsupported, why)
	snap.Files = model.Unavailable[[]model.FileEntry](model.Unsupported, why)
}
