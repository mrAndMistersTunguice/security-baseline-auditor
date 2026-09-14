// Package version reports the build version of sba.
package version

import "runtime/debug"

// Version is set at build time with
// -ldflags "-X github.com/mrAndMistersTunguice/security-baseline-auditor/internal/version.Version=v0.1.0".
var Version = "dev"

// String returns the version, falling back to module and VCS information
// embedded by the Go toolchain.
func String() string {
	if Version != "dev" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		return Version
	}
	if modified == "true" {
		rev += "-dirty"
	}
	return Version + "+" + rev
}
