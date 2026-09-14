// Package files collects ownership and permission metadata for a fixed list
// of security-relevant paths. It never reads file contents.
package files

import (
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// LinuxPaths are the paths inspected on Linux. Rules reference them by
// exact path.
var LinuxPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/tmp",
	"/var/tmp",
}

// Collect stats each path. A path that cannot be inspected is recorded with
// an error instead of failing the whole section.
func Collect(fsys platform.FS, paths []string) model.Section[[]model.FileEntry] {
	entries := make([]model.FileEntry, 0, len(paths))
	for _, p := range paths {
		entry := model.FileEntry{Path: p, UID: -1, GID: -1}
		info, err := fsys.Stat(p)
		switch {
		case err == nil:
			entry.Exists = true
			entry.IsSymlink = info.IsSymlink
			entry.Mode = info.Mode
			entry.ModeString = info.Mode.String()
			entry.UID, entry.GID = info.UID, info.GID
		case platform.IsNotExist(err):
		default:
			entry.Error = err.Error()
		}
		entries = append(entries, entry)
	}
	return model.CollectedSection(entries)
}
