package sshd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// Location is a candidate sshd_config path together with the directory
// that relative Include patterns resolve against.
type Location struct {
	MainFile  string
	ConfigDir string
}

// UnixLocations are the candidates checked on Linux and other Unix systems,
// in priority order. /etc/ssh/sshd_config is the upstream and
// Debian/Ubuntu/RHEL/Fedora/Arch location; openSUSE ships its vendor default
// in /usr/etc/ssh and uses it only when /etc/ssh/sshd_config is absent.
var UnixLocations = []Location{
	{MainFile: "/etc/ssh/sshd_config", ConfigDir: "/etc/ssh"},
	{MainFile: "/usr/etc/ssh/sshd_config", ConfigDir: "/etc/ssh"},
}

// Collect loads the first existing configuration among locations.
func Collect(fsys platform.FS, locations []Location) model.Section[model.SSHDConfig] {
	var tried []string
	for _, loc := range locations {
		tried = append(tried, loc.MainFile)
		if _, err := fsys.Stat(loc.MainFile); err != nil {
			if platform.IsNotExist(err) {
				continue
			}
			return classify(err)
		}
		cfg, err := Load(fsys, loc.MainFile, loc.ConfigDir)
		if err != nil {
			return classify(err)
		}
		return model.CollectedSection(cfg)
	}
	return model.Unavailable[model.SSHDConfig](model.NotFound,
		"no OpenSSH server configuration found (checked "+strings.Join(tried, ", ")+")")
}

func classify(err error) model.Section[model.SSHDConfig] {
	switch {
	case platform.IsPermission(err):
		// A partially read configuration is not sound: an unreadable
		// include may set a value that takes precedence.
		return model.Unavailable[model.SSHDConfig](model.PermissionDenied,
			fmt.Sprintf("cannot read sshd configuration: %v (run as root)", err))
	case errors.Is(err, ErrSyntax):
		return model.Unavailable[model.SSHDConfig](model.Failed,
			fmt.Sprintf("sshd configuration is invalid (sshd would refuse it): %v", err))
	default:
		return model.Unavailable[model.SSHDConfig](model.Failed,
			fmt.Sprintf("cannot load sshd configuration: %v", err))
	}
}
