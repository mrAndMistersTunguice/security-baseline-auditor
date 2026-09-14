// Package hostinfo identifies the operating system being audited.
package hostinfo

import (
	"os"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

const maxSmallFile = 64 << 10

// osReleasePaths are checked in the order documented by os-release(5).
var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// CollectUnix fills distribution and kernel details from os-release(5) and
// procfs. Missing files leave the fields empty; they are informational.
func CollectUnix(fsys platform.FS, host *model.Host) {
	for _, p := range osReleasePaths {
		data, err := fsys.ReadFile(p, maxSmallFile)
		if err != nil {
			continue
		}
		fields := ParseOSRelease(data)
		host.DistroID = fields["ID"]
		host.DistroLike = fields["ID_LIKE"]
		host.PrettyName = fields["PRETTY_NAME"]
		host.Version = fields["VERSION_ID"]
		break
	}
	if data, err := fsys.ReadFile("/proc/sys/kernel/osrelease", maxSmallFile); err == nil {
		host.KernelVersion = strings.TrimSpace(string(data))
	}
}

// Hostname returns the host name or "" if it cannot be determined.
func Hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

// ParseOSRelease parses os-release(5) content: KEY=value lines where value
// may be enclosed in single or double quotes with backslash escapes.
func ParseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !validKey(key) {
			continue
		}
		out[key] = unquote(value)
	}
	return out
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
