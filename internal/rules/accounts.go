package rules

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

const (
	refPasswd    = "https://man7.org/linux/man-pages/man5/passwd.5.html"
	refShadow    = "https://man7.org/linux/man-pages/man5/shadow.5.html"
	refLoginDefs = "https://man7.org/linux/man-pages/man5/login.defs.5.html"
)

var linuxOnly = []string{"linux"}

func accountsData(s *model.Snapshot) (model.Accounts, Result, bool) {
	if res, bad := unavailable("local account database", s.Accounts); bad {
		return model.Accounts{}, res, false
	}
	return s.Accounts.Data, Result{}, true
}

// parseWarnings notes skipped lines so a PASS never silently ignores them.
func parseWarnings(s *model.Snapshot) []string {
	var out []string
	for _, w := range s.Accounts.Warnings {
		out = append(out, "note: "+w)
	}
	return out
}

func accountRules() []Rule {
	return []Rule{
		{
			ID:          "USER-001",
			Title:       "Only root may have UID 0",
			Description: "Any account with UID 0 has full root privileges regardless of its name; additional UID 0 accounts are a common backdoor.",
			Category:    model.CategoryAccounts,
			Severity:    model.SeverityCritical,
			SeverityRationale: "An extra UID 0 account is equivalent to a second root account and typically indicates " +
				"compromise or a severe misconfiguration.",
			Platforms:   linuxOnly,
			Remediation: "Remove the account or assign it a unique non-zero UID after investigating why it exists.",
			References:  []string{refPasswd},
			Check:       checkUIDZero,
		},
		{
			ID:          "USER-002",
			Title:       "Local accounts must not have empty passwords",
			Description: "An empty password field allows authentication without a password wherever null passwords are accepted (for example PAM with nullok).",
			Category:    model.CategoryAccounts,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Access requires no secret at all; whether it is remotely exploitable depends on PAM and " +
				"service configuration, which keeps it below CRITICAL.",
			Platforms:   linuxOnly,
			Remediation: "Lock the account ('passwd -l NAME') or set a strong password.",
			References:  []string{refShadow, refPasswd},
			Check:       checkEmptyPasswords,
		},
		{
			ID:          "USER-003",
			Title:       "Password hashes must not be stored in /etc/passwd",
			Description: "/etc/passwd is world-readable; a hash stored there instead of /etc/shadow can be copied and cracked offline by any local user.",
			Category:    model.CategoryAccounts,
			Severity:    model.SeverityMedium,
			SeverityRationale: "Requires local access and successful offline cracking, but exposes credentials to every " +
				"local user.",
			Platforms:   linuxOnly,
			Remediation: "Run 'pwconv' to move hashes into /etc/shadow, then verify with 'pwck'.",
			References:  []string{refPasswd, refShadow},
			Check:       checkHashInPasswd,
		},
		{
			ID:          "USER-004",
			Title:       "Local accounts must have unique UIDs",
			Description: "Accounts sharing a UID share file ownership and process privileges, which breaks accountability and access separation.",
			Category:    model.CategoryAccounts,
			Severity:    model.SeverityMedium,
			SeverityRationale: "Shared UIDs grant one account the other's access and hide who performed an action, " +
				"but do not by themselves grant elevated privileges (UID 0 duplicates are covered by USER-001).",
			Platforms:   linuxOnly,
			Remediation: "Assign unique UIDs and fix file ownership with 'find / -uid OLD -exec chown NEW {} +'.",
			References:  []string{refPasswd},
			Check:       checkDuplicateUIDs,
		},
		{
			ID:    "USER-005",
			Title: "System accounts should not have interactive login shells",
			Description: "Service accounts (UID below UID_MIN) are not meant for interactive use; a login shell lets an " +
				"attacker who obtains their credentials or keys get a shell.",
			Category: model.CategoryAccounts,
			Severity: model.SeverityLow,
			SeverityRationale: "Exploitation requires another weakness that grants authentication as the service account; " +
				"the shell only widens what can be done afterwards.",
			Platforms: linuxOnly,
			Remediation: "Set the shell to nologin ('usermod -s /usr/sbin/nologin NAME'; the path is /sbin/nologin on " +
				"RHEL-family systems) unless the account genuinely requires one.",
			References: []string{refPasswd, refLoginDefs},
			Check:      checkSystemShells,
		},
	}
}

func checkUIDZero(s *model.Snapshot) Result {
	acc, res, ok := accountsData(s)
	if !ok {
		return res
	}
	var extra []string
	for _, u := range acc.Users {
		if u.UID == 0 && u.Name != "root" {
			extra = append(extra, fmt.Sprintf("%s has UID 0 (/etc/passwd line %d)", u.Name, u.Line))
		}
	}
	if len(extra) > 0 {
		return Fail(fmt.Sprintf("%d account(s) other than root have UID 0", len(extra)), append(extra, parseWarnings(s)...)...)
	}
	return Pass("only root has UID 0", append([]string{fmt.Sprintf("%d accounts inspected", len(acc.Users))}, parseWarnings(s)...)...)
}

func checkEmptyPasswords(s *model.Snapshot) Result {
	acc, res, ok := accountsData(s)
	if !ok {
		return res
	}
	var empty []string
	shadowed := 0
	for _, u := range acc.Users {
		switch u.PasswordField {
		case model.PasswordEmpty:
			empty = append(empty, fmt.Sprintf("%s has an empty password field in /etc/passwd", u.Name))
		case model.PasswordShadowed:
			shadowed++
		}
	}
	if shadowed == 0 && len(empty) == 0 {
		return Pass("no account has an empty password field")
	}
	if res, bad := unavailable("/etc/shadow", acc.Shadow); bad {
		if len(empty) > 0 {
			// Conclusive without /etc/shadow, but the list may be incomplete.
			return Fail("accounts with empty passwords exist", append(empty,
				"note: /etc/shadow was not inspected ("+res.Message+"); more accounts may be affected")...)
		}
		res.Evidence = append(res.Evidence, fmt.Sprintf("%d account(s) keep their password in /etc/shadow", shadowed))
		return res
	}
	for _, e := range acc.Shadow.Data {
		if e.Password == model.PasswordEmpty {
			empty = append(empty, fmt.Sprintf("%s has an empty password in /etc/shadow (line %d)", e.Name, e.Line))
		}
	}
	if len(empty) > 0 {
		return Fail("accounts with empty passwords exist", empty...)
	}
	evidence := []string{fmt.Sprintf("%d shadow entries inspected", len(acc.Shadow.Data))}
	for _, w := range acc.Shadow.Warnings {
		evidence = append(evidence, "note: "+w)
	}
	return Pass("no account has an empty password", evidence...)
}

func checkHashInPasswd(s *model.Snapshot) Result {
	acc, res, ok := accountsData(s)
	if !ok {
		return res
	}
	var found []string
	for _, u := range acc.Users {
		if u.PasswordField == model.PasswordHash {
			found = append(found, fmt.Sprintf("%s has a password hash in /etc/passwd (line %d)", u.Name, u.Line))
		}
	}
	if len(found) > 0 {
		return Fail("password hashes are stored in world-readable /etc/passwd", found...)
	}
	return Pass("no password hashes in /etc/passwd", parseWarnings(s)...)
}

func checkDuplicateUIDs(s *model.Snapshot) Result {
	acc, res, ok := accountsData(s)
	if !ok {
		return res
	}
	byUID := map[uint32][]string{}
	for _, u := range acc.Users {
		byUID[u.UID] = append(byUID[u.UID], u.Name)
	}
	var dups []string
	for uid, names := range byUID {
		if len(names) > 1 {
			dups = append(dups, fmt.Sprintf("UID %d is shared by %s", uid, strings.Join(names, ", ")))
		}
	}
	slices.Sort(dups)
	if len(dups) > 0 {
		return Fail("duplicate UIDs found", dups...)
	}
	return Pass("all UIDs are unique", parseWarnings(s)...)
}

// Accounts that conventionally have a special-purpose shell.
var shellExemptAccounts = map[string]bool{"root": true, "sync": true, "shutdown": true, "halt": true}

func nonInteractiveShell(shell string) bool {
	switch path.Base(shell) {
	case "nologin", "false":
		return true
	}
	return false
}

func checkSystemShells(s *model.Snapshot) Result {
	acc, res, ok := accountsData(s)
	if !ok {
		return res
	}
	var found []string
	for _, u := range acc.Users {
		// UID 0 accounts are covered by USER-001.
		if u.UID == 0 || int64(u.UID) >= int64(acc.UIDMin) || shellExemptAccounts[u.Name] {
			continue
		}
		if !nonInteractiveShell(u.Shell) {
			shell := u.Shell
			if shell == "" {
				shell = "(empty: defaults to /bin/sh)"
			}
			found = append(found, fmt.Sprintf("%s (UID %d) has shell %s", u.Name, u.UID, shell))
		}
	}
	evidence := append(slices.Clone(found), fmt.Sprintf("system accounts are UID < %d (source: %s)", acc.UIDMin, acc.UIDMinSource))
	if len(found) > 0 {
		return Fail(fmt.Sprintf("%d system account(s) have an interactive shell", len(found)), evidence...)
	}
	return Pass("all system accounts have non-interactive shells", evidence...)
}
