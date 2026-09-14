package rules

import (
	"fmt"
	"io/fs"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

const (
	refSudoers = "https://www.sudo.ws/docs/man/sudoers.man/"
	refChmod   = "https://man7.org/linux/man-pages/man1/chmod.1.html"
)

// filePolicy describes permissions a file must not have.
type filePolicy struct {
	path string
	// forbidden permission bits that must all be clear.
	forbidden fs.FileMode
	// rootOwned requires the file to be owned by UID 0.
	rootOwned bool
}

func fileEvidence(e model.FileEntry) string {
	s := fmt.Sprintf("%s mode %s (%04o) owner uid %d gid %d", e.Path, e.ModeString, e.Mode.Perm(), e.UID, e.GID)
	if e.IsSymlink {
		s += " (symlink; target metadata shown)"
	}
	return s
}

func fileCheck(p filePolicy) func(*model.Snapshot) Result {
	return func(s *model.Snapshot) Result {
		if res, bad := unavailable("file metadata", s.Files); bad {
			return res
		}
		e, ok := model.FindFile(s.Files.Data, p.path)
		switch {
		case !ok:
			return Error(p.path + " was not collected (collector and rule are out of sync)")
		case e.Error != "":
			if !s.Host.Elevated {
				return Skip("cannot inspect "+p.path, e.Error)
			}
			return Error("cannot inspect "+p.path, e.Error)
		case !e.Exists:
			return Skip(p.path + " does not exist")
		}

		var problems []string
		if bad := e.Mode.Perm() & p.forbidden; bad != 0 {
			problems = append(problems, fmt.Sprintf("permission bits %04o must not be set (allowed at most %04o)", bad, 0o777&^p.forbidden))
		}
		if p.rootOwned {
			switch {
			case e.UID < 0:
				return Skip("file ownership is not available on this platform", fileEvidence(e))
			case e.UID != 0:
				problems = append(problems, fmt.Sprintf("owned by uid %d instead of root", e.UID))
			}
		}
		evidence := append([]string{fileEvidence(e)}, problems...)
		if len(problems) > 0 {
			return Fail(p.path+" has unsafe ownership or permissions", evidence...)
		}
		return Pass(p.path+" ownership and permissions are acceptable", evidence...)
	}
}

func checkStickyTempDirs(s *model.Snapshot) Result {
	if res, bad := unavailable("file metadata", s.Files); bad {
		return res
	}
	var evidence, problems []string
	inspected := 0
	for _, dir := range []string{"/tmp", "/var/tmp"} {
		e, ok := model.FindFile(s.Files.Data, dir)
		if !ok || !e.Exists || e.Error != "" {
			continue
		}
		inspected++
		evidence = append(evidence, fileEvidence(e))
		if e.Mode.Perm()&0o002 != 0 && e.Mode&fs.ModeSticky == 0 {
			problems = append(problems, dir+" is world-writable without the sticky bit")
		}
	}
	if inspected == 0 {
		return Skip("no temporary directories could be inspected")
	}
	if len(problems) > 0 {
		return Fail("world-writable temporary directories lack the sticky bit", append(problems, evidence...)...)
	}
	return Pass("temporary directories are protected by the sticky bit or not world-writable", evidence...)
}

func fileRules() []Rule {
	return []Rule{
		{
			ID:          "FILE-001",
			Title:       "/etc/shadow must not be accessible to other users",
			Description: "/etc/shadow contains password hashes; it must be owned by root, not group-writable and have no permissions for others.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Read access exposes every password hash to offline cracking; write access allows " +
				"setting any account's password, including root's.",
			Platforms:   linuxOnly,
			Remediation: "chown root /etc/shadow && chmod 0640 /etc/shadow (Debian family, group shadow) or chmod 0000 (RHEL family).",
			References:  []string{refShadow, refChmod},
			Check:       fileCheck(filePolicy{path: "/etc/shadow", forbidden: 0o027, rootOwned: true}),
		},
		{
			ID:          "FILE-002",
			Title:       "/etc/gshadow must not be accessible to other users",
			Description: "/etc/gshadow contains group passwords and administrator lists; it must be owned by root with no permissions for others.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityMedium,
			SeverityRationale: "Group passwords are rarely used, so exposure usually has less impact than /etc/shadow, " +
				"but write access still allows joining privileged groups.",
			Platforms:   linuxOnly,
			Remediation: "chown root /etc/gshadow && chmod 0640 /etc/gshadow (or 0000 on RHEL-family systems).",
			References:  []string{refChmod},
			Check:       fileCheck(filePolicy{path: "/etc/gshadow", forbidden: 0o027, rootOwned: true}),
		},
		{
			ID:          "FILE-003",
			Title:       "/etc/passwd must be writable only by root",
			Description: "/etc/passwd defines UIDs and shells; it must be owned by root and not writable by group or others.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityCritical,
			SeverityRationale: "Write access lets any user add a UID 0 account or change root's password field, an " +
				"immediate and reliable privilege escalation.",
			Platforms:   linuxOnly,
			Remediation: "chown root:root /etc/passwd && chmod 0644 /etc/passwd",
			References:  []string{refPasswd, refChmod},
			Check:       fileCheck(filePolicy{path: "/etc/passwd", forbidden: 0o022, rootOwned: true}),
		},
		{
			ID:          "FILE-004",
			Title:       "/etc/group must be writable only by root",
			Description: "/etc/group defines group membership, including administrative groups such as sudo or wheel.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Write access lets a user join an administrative group and typically gain root through " +
				"sudo on the next login.",
			Platforms:   linuxOnly,
			Remediation: "chown root:root /etc/group && chmod 0644 /etc/group",
			References:  []string{refChmod},
			Check:       fileCheck(filePolicy{path: "/etc/group", forbidden: 0o022, rootOwned: true}),
		},
		{
			ID:          "FILE-005",
			Title:       "/etc/sudoers must be owned by root and not writable by others",
			Description: "The sudoers policy decides who may run commands as root.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Write access to the policy is a direct path to root; sudo refuses some unsafe modes, " +
				"which limits but does not remove the risk.",
			Platforms:   linuxOnly,
			Remediation: "chown root:root /etc/sudoers && chmod 0440 /etc/sudoers (edit only with visudo).",
			References:  []string{refSudoers},
			Check:       fileCheck(filePolicy{path: "/etc/sudoers", forbidden: 0o027, rootOwned: true}),
		},
		{
			ID:          "FILE-006",
			Title:       "/etc/ssh/sshd_config must be writable only by root",
			Description: "The SSH server configuration controls remote authentication.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Write access allows weakening remote authentication for every account (for example " +
				"enabling root login or empty passwords) the next time sshd reloads its configuration.",
			Platforms:   linuxOnly,
			Remediation: "chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config",
			References:  []string{refSSHDConfig},
			Check:       fileCheck(filePolicy{path: "/etc/ssh/sshd_config", forbidden: 0o022, rootOwned: true}),
		},
		{
			ID:          "FILE-007",
			Title:       "World-writable temporary directories must have the sticky bit",
			Description: "Without the sticky bit on /tmp and /var/tmp any user can delete or replace other users' files.",
			Category:    model.CategoryFiles,
			Severity:    model.SeverityMedium,
			SeverityRationale: "Enables tampering with other users' temporary files and symlink races against " +
				"privileged programs, which depends on a vulnerable program to become an escalation.",
			Platforms:   linuxOnly,
			Remediation: "chmod 1777 /tmp /var/tmp",
			References:  []string{refChmod},
			Check:       checkStickyTempDirs,
		},
	}
}
