package rules

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

const (
	refSSHDConfig = "https://man.openbsd.org/sshd_config"
	refRFC8758    = "https://www.rfc-editor.org/rfc/rfc8758"
	refRFC9142    = "https://www.rfc-editor.org/rfc/rfc9142"
)

var sshPlatforms = []string{"linux", "windows"}

// sshSetting is the resolved value of one sshd keyword.
type sshSetting struct {
	value    string // lower-cased first argument
	evidence string
}

// display names keep evidence readable (keywords are stored lower-cased).
var sshDisplay = map[string]string{
	"permitrootlogin":              "PermitRootLogin",
	"passwordauthentication":       "PasswordAuthentication",
	"kbdinteractiveauthentication": "KbdInteractiveAuthentication",
	"usepam":                       "UsePAM",
	"permitemptypasswords":         "PermitEmptyPasswords",
	"permituserenvironment":        "PermitUserEnvironment",
	"maxauthtries":                 "MaxAuthTries",
	"x11forwarding":                "X11Forwarding",
	"ciphers":                      "Ciphers",
	"macs":                         "MACs",
	"kexalgorithms":                "KexAlgorithms",
}

func location(d model.SSHDirective) string {
	return fmt.Sprintf("%s:%d", d.File, d.Line)
}

func describe(d model.SSHDirective) string {
	s := fmt.Sprintf("%s %s (%s)", sshDisplay[d.Keyword], strings.Join(d.Args, " "), location(d))
	if d.Match != "" {
		s = fmt.Sprintf("%s %s in 'Match %s' (%s)", sshDisplay[d.Keyword], strings.Join(d.Args, " "), d.Match, location(d))
	}
	return s
}

// globalSetting resolves the effective global value, falling back to the
// documented OpenSSH default.
func globalSetting(cfg model.SSHDConfig, keyword, def string) sshSetting {
	if d, ok := cfg.Global(keyword); ok {
		return sshSetting{value: strings.ToLower(d.Args[0]), evidence: describe(d)}
	}
	return sshSetting{
		value:    def,
		evidence: fmt.Sprintf("%s not set; OpenSSH default is %q", sshDisplay[keyword], def),
	}
}

// sshConfig returns the collected configuration or a SKIP/ERROR result.
func sshConfig(s *model.Snapshot) (model.SSHDConfig, Result, bool) {
	if res, bad := unavailable("OpenSSH server configuration", s.SSHD); bad {
		return model.SSHDConfig{}, res, false
	}
	return s.SSHD.Data, Result{}, true
}

// sshValueCheck evaluates a keyword whose value is bad according to isBad.
// A bad value inside any Match block also fails the rule, because it
// applies to every connection matching that block.
func sshValueCheck(keyword, def string, isBad func(string) bool, failMsg, passMsg string) func(*model.Snapshot) Result {
	return func(s *model.Snapshot) Result {
		cfg, res, ok := sshConfig(s)
		if !ok {
			return res
		}
		global := globalSetting(cfg, keyword, def)
		var badConditional []string
		for _, d := range cfg.Conditional(keyword) {
			if isBad(strings.ToLower(d.Args[0])) {
				badConditional = append(badConditional, describe(d))
			}
		}
		evidence := append([]string{global.evidence}, badConditional...)
		switch {
		case isBad(global.value):
			return Fail(failMsg, evidence...)
		case len(badConditional) > 0:
			return Fail(failMsg+" for connections matching a Match block", evidence...)
		default:
			return Pass(passMsg, evidence...)
		}
	}
}

func sshRules() []Rule {
	return []Rule{
		{
			ID:          "SSH-001",
			Title:       "SSH root login with a password must not be allowed",
			Description: "PermitRootLogin yes lets anyone who knows or guesses the root password log in remotely as root.",
			Category:    model.CategorySSH,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Direct password-based root login exposes the most privileged account to remote " +
				"brute-force and credential-stuffing attacks and yields full system control on success.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'PermitRootLogin no' (or 'prohibit-password' if key-based root access is required) and reload sshd.",
			References:  []string{refSSHDConfig},
			Check: sshValueCheck("permitrootlogin", "prohibit-password",
				func(v string) bool { return v == "yes" },
				"root login with password authentication is permitted",
				"root login with a password is not permitted"),
		},
		{
			ID:          "SSH-002",
			Title:       "SSH root login should be disabled entirely",
			Description: "Any PermitRootLogin value other than 'no' allows remote root sessions (for example with keys), bypassing per-user accountability.",
			Category:    model.CategorySSH,
			Severity:    model.SeverityLow,
			SeverityRationale: "Key-based root login is not directly brute-forceable, so the residual risk is loss of " +
				"accountability and a larger blast radius for a stolen key rather than an exploitable weakness.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'PermitRootLogin no'; administrators log in as themselves and elevate with sudo.",
			References:  []string{refSSHDConfig},
			Check: sshValueCheck("permitrootlogin", "prohibit-password",
				func(v string) bool { return v != "no" },
				"remote root login is permitted",
				"remote root login is disabled"),
		},
		{
			ID:          "SSH-003",
			Title:       "SSH password authentication should be disabled",
			Description: "PasswordAuthentication yes accepts passwords, which can be guessed, reused or phished, instead of requiring keys or certificates.",
			Category:    model.CategorySSH,
			Severity:    model.SeverityMedium,
			SeverityRationale: "Password login enables online guessing against every account, but exploitation still " +
				"requires a weak or leaked password, so the impact is conditional.",
			Platforms:   sshPlatforms,
			Remediation: "Deploy SSH keys for all users, then set 'PasswordAuthentication no'.",
			References:  []string{refSSHDConfig},
			Check: sshValueCheck("passwordauthentication", "yes",
				func(v string) bool { return v != "no" },
				"password authentication is enabled",
				"password authentication is disabled"),
		},
		{
			ID:    "SSH-004",
			Title: "SSH keyboard-interactive authentication via PAM should be disabled",
			Description: "With UsePAM yes, keyboard-interactive authentication usually prompts for the account password, " +
				"re-enabling password logins even when PasswordAuthentication is no.",
			Category: model.CategorySSH,
			Severity: model.SeverityMedium,
			SeverityRationale: "It is an equivalent path to password authentication and carries the same conditional " +
				"risk of password guessing.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'KbdInteractiveAuthentication no' unless PAM is used for a second factor that requires it.",
			References:  []string{refSSHDConfig},
			Check:       checkKbdInteractive,
		},
		{
			ID:          "SSH-005",
			Title:       "SSH must not permit empty passwords",
			Description: "PermitEmptyPasswords yes allows login to accounts that have no password at all.",
			Category:    model.CategorySSH,
			Severity:    model.SeverityHigh,
			SeverityRationale: "Any account with an empty password becomes remotely accessible without credentials; " +
				"no guessing is required.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'PermitEmptyPasswords no' (the OpenSSH default) and lock or set passwords for such accounts.",
			References:  []string{refSSHDConfig},
			Check: sshValueCheck("permitemptypasswords", "no",
				func(v string) bool { return v != "no" },
				"empty passwords are permitted",
				"empty passwords are not permitted"),
		},
		{
			ID:    "SSH-006",
			Title: "SSH must not process user-supplied environment files",
			Description: "PermitUserEnvironment lets users set variables through ~/.ssh/environment or authorized_keys " +
				"options, which can bypass restrictions such as ForceCommand (for example via LD_PRELOAD).",
			Category: model.CategorySSH,
			Severity: model.SeverityMedium,
			SeverityRationale: "Exploitation requires an authenticated user, but it can defeat restricted-shell and " +
				"forced-command setups that the configuration relies on.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'PermitUserEnvironment no' (the OpenSSH default).",
			References:  []string{refSSHDConfig},
			Check: sshValueCheck("permituserenvironment", "no",
				func(v string) bool { return v != "no" },
				"user environment processing is enabled",
				"user environment processing is disabled"),
		},
		{
			ID:          "SSH-007",
			Title:       "SSH MaxAuthTries should be 4 or lower",
			Description: "MaxAuthTries limits authentication attempts per connection; high values make online guessing cheaper.",
			Category:    model.CategorySSH,
			Severity:    model.SeverityLow,
			SeverityRationale: "The setting only slows guessing per connection; attackers can reconnect, so the " +
				"security gain is incremental.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'MaxAuthTries 4' or lower.",
			References:  []string{refSSHDConfig},
			Check:       checkMaxAuthTries,
		},
		{
			ID:          "SSH-008",
			Title:       "SSH X11 forwarding should be disabled",
			Description: "X11Forwarding exposes the client's X display to the server, where a compromised server can capture input or screen content.",
			Category:    model.CategorySSH,
			Severity:    model.SeverityLow,
			SeverityRationale: "The risk falls mainly on clients connecting to a compromised server and requires " +
				"the client to request forwarding.",
			Platforms:   sshPlatforms,
			Remediation: "Set 'X11Forwarding no' unless graphical forwarding is required.",
			References:  []string{refSSHDConfig},
			Check: sshValueCheck("x11forwarding", "no",
				func(v string) bool { return v != "no" },
				"X11 forwarding is enabled",
				"X11 forwarding is disabled"),
		},
		{
			ID:    "SSH-009",
			Title: "SSH must not enable weak ciphers, MACs or key exchange algorithms",
			Description: "Explicit Ciphers, MACs or KexAlgorithms settings can re-enable algorithms that modern OpenSSH " +
				"disables by default: CBC-mode and RC4 ciphers, MD5/truncated-SHA1/RIPEMD MACs and SHA-1 based key exchange.",
			Category: model.CategorySSH,
			Severity: model.SeverityMedium,
			SeverityRationale: "Practical attacks require a network position and, for most of these algorithms, " +
				"significant effort, but they weaken the confidentiality or integrity guarantees of every session.",
			Platforms: sshPlatforms,
			Remediation: "Remove the listed algorithms from Ciphers, MACs and KexAlgorithms, or remove the directives to " +
				"use the OpenSSH defaults (on RHEL-family systems adjust the system crypto policy instead).",
			References: []string{refSSHDConfig, refRFC8758, refRFC9142},
			Check:      checkWeakAlgorithms,
		},
	}
}

func checkKbdInteractive(s *model.Snapshot) Result {
	cfg, res, ok := sshConfig(s)
	if !ok {
		return res
	}
	// UsePAM is not permitted inside Match blocks, so the global value is
	// authoritative. The upstream default is "no"; many distributions set
	// "yes" explicitly.
	pam := globalSetting(cfg, "usepam", "no")
	kbd := globalSetting(cfg, "kbdinteractiveauthentication", "yes")
	var badConditional []string
	for _, d := range cfg.Conditional("kbdinteractiveauthentication") {
		if strings.ToLower(d.Args[0]) != "no" {
			badConditional = append(badConditional, describe(d))
		}
	}
	evidence := append([]string{kbd.evidence, pam.evidence}, badConditional...)
	if pam.value != "yes" {
		return Pass("PAM is disabled, so keyboard-interactive authentication has no password backend", evidence...)
	}
	switch {
	case kbd.value != "no":
		return Fail("keyboard-interactive authentication is enabled with PAM", evidence...)
	case len(badConditional) > 0:
		return Fail("keyboard-interactive authentication is enabled with PAM for connections matching a Match block", evidence...)
	}
	return Pass("keyboard-interactive authentication is disabled", evidence...)
}

const maxAuthTriesLimit = 4

func checkMaxAuthTries(s *model.Snapshot) Result {
	cfg, res, ok := sshConfig(s)
	if !ok {
		return res
	}
	directives := cfg.Conditional("maxauthtries")
	global, hasGlobal := cfg.Global("maxauthtries")
	if hasGlobal {
		directives = append([]model.SSHDirective{global}, directives...)
	}
	var evidence, bad []string
	if !hasGlobal {
		evidence = append(evidence, "MaxAuthTries not set; OpenSSH default is 6")
		bad = append(bad, "default 6")
	}
	for _, d := range directives {
		n, err := strconv.Atoi(d.Args[0])
		if err != nil {
			return Error("MaxAuthTries has a non-numeric value, which sshd rejects", describe(d))
		}
		evidence = append(evidence, describe(d))
		if n > maxAuthTriesLimit {
			bad = append(bad, describe(d))
		}
	}
	if len(bad) > 0 {
		return Fail(fmt.Sprintf("MaxAuthTries allows more than %d attempts", maxAuthTriesLimit), evidence...)
	}
	return Pass(fmt.Sprintf("MaxAuthTries is at most %d", maxAuthTriesLimit), evidence...)
}

// Weak algorithm names. They are absent from the OpenSSH server defaults
// since at least OpenSSH 7.x/8.x, so unset directives pass.
var weakAlgorithms = map[string][]string{
	"ciphers": {
		"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
		"blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256",
	},
	"macs": {
		"hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
		"hmac-sha1-96", "hmac-sha1-96-etm@openssh.com",
		"hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-ripemd160-etm@openssh.com",
	},
	"kexalgorithms": {
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
	},
}

// weakInList returns weak algorithms enabled by an algorithm list value.
// A leading '-' removes algorithms from the defaults and cannot add weak
// ones; '+' and '^' add the listed algorithms to the defaults; otherwise
// the list replaces the defaults. Wildcard patterns are expanded against
// the weak list.
func weakInList(value string, weak []string) []string {
	if strings.HasPrefix(value, "-") {
		return nil
	}
	value = strings.TrimLeft(value, "+^")
	var found []string
	for _, item := range strings.Split(strings.ToLower(value), ",") {
		item = strings.TrimSpace(item)
		if item == "" || strings.HasPrefix(item, "!") {
			continue
		}
		for _, w := range weak {
			if ok, err := path.Match(item, w); err == nil && ok {
				found = append(found, w)
			}
		}
	}
	return found
}

func checkWeakAlgorithms(s *model.Snapshot) Result {
	cfg, res, ok := sshConfig(s)
	if !ok {
		return res
	}
	var evidence []string
	failed := false
	for _, kw := range []string{"ciphers", "macs", "kexalgorithms"} {
		// These keywords are not allowed in Match blocks.
		d, ok := cfg.Global(kw)
		if !ok {
			evidence = append(evidence, sshDisplay[kw]+" not set; OpenSSH defaults contain none of the weak algorithms checked")
			continue
		}
		if weak := weakInList(d.Args[0], weakAlgorithms[kw]); len(weak) > 0 {
			failed = true
			evidence = append(evidence, fmt.Sprintf("%s enables weak algorithms: %s (%s)", sshDisplay[kw], strings.Join(weak, ", "), location(d)))
		} else {
			evidence = append(evidence, fmt.Sprintf("%s contains none of the weak algorithms checked (%s)", sshDisplay[kw], location(d)))
		}
	}
	if failed {
		return Fail("weak SSH algorithms are enabled", evidence...)
	}
	return Pass("no weak SSH algorithms are enabled", evidence...)
}
