package rules

import "slices"

// Builtin returns a fresh copy of the built-in rule catalog, ordered by ID
// group as defined below.
func Builtin() []Rule {
	return slices.Concat(sshRules(), accountRules(), firewallRules(), fileRules())
}
