package accounts

import (
	"fmt"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

const (
	PasswdPath    = "/etc/passwd"
	ShadowPath    = "/etc/shadow"
	LoginDefsPath = "/etc/login.defs"

	maxDatabaseSize = 32 << 20
	maxLoginDefs    = 1 << 20

	// DefaultUIDMin is the shadow-utils default when login.defs does not
	// set UID_MIN.
	DefaultUIDMin = 1000
)

// Collect reads the local Unix account databases.
func Collect(fsys platform.FS) model.Section[model.Accounts] {
	data, err := fsys.ReadFile(PasswdPath, maxDatabaseSize)
	if err != nil {
		status := model.Failed
		switch {
		case platform.IsNotExist(err):
			status = model.NotFound
		case platform.IsPermission(err):
			status = model.PermissionDenied
		}
		return model.Unavailable[model.Accounts](status, fmt.Sprintf("cannot read %s: %v", PasswdPath, err))
	}
	users, warnings := ParsePasswd(data)

	acc := model.Accounts{Users: users}
	acc.Shadow = collectShadow(fsys)
	acc.UIDMin, acc.UIDMinSource, warnings = uidMin(fsys, warnings)

	sec := model.CollectedSection(acc)
	sec.Warnings = warnings
	return sec
}

func collectShadow(fsys platform.FS) model.Section[[]model.ShadowEntry] {
	data, err := fsys.ReadFile(ShadowPath, maxDatabaseSize)
	switch {
	case err == nil:
		entries, warnings := ParseShadow(data)
		sec := model.CollectedSection(entries)
		sec.Warnings = warnings
		return sec
	case platform.IsPermission(err):
		return model.Unavailable[[]model.ShadowEntry](model.PermissionDenied,
			"reading "+ShadowPath+" requires root privileges")
	case platform.IsNotExist(err):
		return model.Unavailable[[]model.ShadowEntry](model.NotFound, ShadowPath+" does not exist")
	default:
		return model.Unavailable[[]model.ShadowEntry](model.Failed, fmt.Sprintf("cannot read %s: %v", ShadowPath, err))
	}
}

func uidMin(fsys platform.FS, warnings []string) (int, string, []string) {
	data, err := fsys.ReadFile(LoginDefsPath, maxLoginDefs)
	if err != nil {
		if !platform.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("cannot read %s: %v", LoginDefsPath, err))
		}
		return DefaultUIDMin, fmt.Sprintf("default %d (%s not readable)", DefaultUIDMin, LoginDefsPath), warnings
	}
	n, found, err := ParseUIDMin(data)
	if err != nil {
		warnings = append(warnings, err.Error())
		return DefaultUIDMin, fmt.Sprintf("default %d (%s has an invalid UID_MIN)", DefaultUIDMin, LoginDefsPath), warnings
	}
	if !found {
		return DefaultUIDMin, fmt.Sprintf("default %d (UID_MIN not set in %s)", DefaultUIDMin, LoginDefsPath), warnings
	}
	return n, LoginDefsPath, warnings
}
