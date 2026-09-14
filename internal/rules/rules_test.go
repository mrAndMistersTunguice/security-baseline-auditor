package rules

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/accounts"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector/sshd"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func TestCatalogIsValid(t *testing.T) {
	if err := Validate(Builtin()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsBrokenRules(t *testing.T) {
	good := Builtin()[0]
	tests := map[string]func(r *Rule){
		"bad id":         func(r *Rule) { r.ID = "ssh-1" },
		"no title":       func(r *Rule) { r.Title = "" },
		"bad severity":   func(r *Rule) { r.Severity = 0 },
		"no check":       func(r *Rule) { r.Check = nil },
		"http reference": func(r *Rule) { r.References = []string{"http://example.com"} },
		"no platforms":   func(r *Rule) { r.Platforms = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)
			if Validate([]Rule{r}) == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if Validate([]Rule{good, good}) == nil {
		t.Error("duplicate IDs must be rejected")
	}
}

func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range Builtin() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return Rule{}
}

// sshSnapshot parses config text with the real sshd parser.
func sshSnapshot(t *testing.T, config string) *model.Snapshot {
	t.Helper()
	fsys := platformtest.NewFS().AddText("/etc/ssh/sshd_config", config)
	return &model.Snapshot{SSHD: sshd.Collect(fsys, sshd.UnixLocations)}
}

type ruleCase struct {
	name       string
	snap       *model.Snapshot
	want       model.Status
	evidenceIn string // substring expected somewhere in evidence or message
}

func runCases(t *testing.T, id string, cases []ruleCase) {
	t.Helper()
	r := ruleByID(t, id)
	for _, tc := range cases {
		t.Run(id+"/"+tc.name, func(t *testing.T) {
			res := r.Check(tc.snap)
			if res.Status != tc.want {
				t.Fatalf("status = %s, want %s (message %q, evidence %q)", res.Status, tc.want, res.Message, res.Evidence)
			}
			if res.Message == "" {
				t.Error("result must have a message")
			}
			if tc.evidenceIn != "" {
				all := res.Message + "\n" + strings.Join(res.Evidence, "\n")
				if !strings.Contains(all, tc.evidenceIn) {
					t.Errorf("output %q does not contain %q", all, tc.evidenceIn)
				}
			}
		})
	}
}

func TestSSHRulesSectionStates(t *testing.T) {
	states := []struct {
		sec  model.Section[model.SSHDConfig]
		want model.Status
	}{
		{model.Unavailable[model.SSHDConfig](model.NotFound, "not installed"), model.StatusSkip},
		{model.Unavailable[model.SSHDConfig](model.PermissionDenied, "run as root"), model.StatusSkip},
		{model.Unavailable[model.SSHDConfig](model.Unsupported, "n/a"), model.StatusSkip},
		{model.Unavailable[model.SSHDConfig](model.Failed, "bad syntax"), model.StatusError},
	}
	for _, r := range sshRules() {
		for _, st := range states {
			if got := r.Check(&model.Snapshot{SSHD: st.sec}); got.Status != st.want {
				t.Errorf("%s with section %s: status %s, want %s", r.ID, st.sec.Status, got.Status, st.want)
			}
		}
	}
}

func TestSSHRootLogin(t *testing.T) {
	runCases(t, "SSH-001", []ruleCase{
		{"explicit yes", sshSnapshot(t, "PermitRootLogin yes\n"), model.StatusFail, "sshd_config:1"},
		{"value case-insensitive", sshSnapshot(t, "PermitRootLogin YES\n"), model.StatusFail, ""},
		{"default", sshSnapshot(t, "Port 22\n"), model.StatusPass, "OpenSSH default"},
		{"prohibit-password", sshSnapshot(t, "PermitRootLogin prohibit-password\n"), model.StatusPass, ""},
		{"deprecated without-password", sshSnapshot(t, "PermitRootLogin without-password\n"), model.StatusPass, ""},
		{"first value wins", sshSnapshot(t, "PermitRootLogin no\nPermitRootLogin yes\n"), model.StatusPass, ""},
		{"yes inside Match", sshSnapshot(t, "PermitRootLogin no\nMatch Address 192.0.2.0/24\n  PermitRootLogin yes\n"), model.StatusFail, "Match Address 192.0.2.0/24"},
	})
	runCases(t, "SSH-002", []ruleCase{
		{"no", sshSnapshot(t, "PermitRootLogin no\n"), model.StatusPass, ""},
		{"default allows keys", sshSnapshot(t, ""), model.StatusFail, "prohibit-password"},
		{"forced-commands-only", sshSnapshot(t, "PermitRootLogin forced-commands-only\n"), model.StatusFail, ""},
	})
}

func TestSSHPasswordRules(t *testing.T) {
	runCases(t, "SSH-003", []ruleCase{
		{"default is yes", sshSnapshot(t, ""), model.StatusFail, "default"},
		{"disabled", sshSnapshot(t, "PasswordAuthentication no\n"), model.StatusPass, ""},
		{"re-enabled for an address range", sshSnapshot(t, "PasswordAuthentication no\nMatch Address 10.0.0.0/8\n PasswordAuthentication yes\n"), model.StatusFail, "Match"},
		{"disabled in match too", sshSnapshot(t, "PasswordAuthentication no\nMatch User bob\n PasswordAuthentication no\n"), model.StatusPass, ""},
	})
	runCases(t, "SSH-004", []ruleCase{
		{"upstream defaults: no PAM", sshSnapshot(t, ""), model.StatusPass, "UsePAM not set"},
		{"PAM with kbd default", sshSnapshot(t, "UsePAM yes\n"), model.StatusFail, ""},
		{"PAM with deprecated alias off", sshSnapshot(t, "UsePAM yes\nChallengeResponseAuthentication no\n"), model.StatusPass, ""},
		{"PAM, kbd enabled in Match", sshSnapshot(t, "UsePAM yes\nKbdInteractiveAuthentication no\nMatch Group admins\n KbdInteractiveAuthentication yes\n"), model.StatusFail, "Match Group admins"},
	})
	runCases(t, "SSH-005", []ruleCase{
		{"default", sshSnapshot(t, ""), model.StatusPass, ""},
		{"enabled", sshSnapshot(t, "PermitEmptyPasswords yes\n"), model.StatusFail, ""},
	})
}

func TestSSHOtherRules(t *testing.T) {
	runCases(t, "SSH-006", []ruleCase{
		{"default", sshSnapshot(t, ""), model.StatusPass, ""},
		{"pattern list counts as enabled", sshSnapshot(t, "PermitUserEnvironment LANG,LC_*\n"), model.StatusFail, ""},
	})
	runCases(t, "SSH-007", []ruleCase{
		{"default 6", sshSnapshot(t, ""), model.StatusFail, "default"},
		{"3", sshSnapshot(t, "MaxAuthTries 3\n"), model.StatusPass, ""},
		{"4 is the limit", sshSnapshot(t, "MaxAuthTries 4\n"), model.StatusPass, ""},
		{"raised in Match", sshSnapshot(t, "MaxAuthTries 3\nMatch User ci\n MaxAuthTries 10\n"), model.StatusFail, "Match User ci"},
		{"not a number", sshSnapshot(t, "MaxAuthTries lots\n"), model.StatusError, ""},
	})
	runCases(t, "SSH-008", []ruleCase{
		{"default", sshSnapshot(t, ""), model.StatusPass, ""},
		{"enabled", sshSnapshot(t, "X11Forwarding yes\n"), model.StatusFail, ""},
	})
	runCases(t, "SSH-009", []ruleCase{
		{"defaults", sshSnapshot(t, ""), model.StatusPass, ""},
		{"modern explicit list", sshSnapshot(t, "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"), model.StatusPass, ""},
		{"cbc cipher", sshSnapshot(t, "Ciphers aes256-ctr,aes256-cbc\n"), model.StatusFail, "aes256-cbc"},
		{"appended to defaults", sshSnapshot(t, "KexAlgorithms +diffie-hellman-group1-sha1\n"), model.StatusFail, "group1-sha1"},
		{"prepended", sshSnapshot(t, "MACs ^hmac-md5\n"), model.StatusFail, "hmac-md5"},
		{"removal cannot enable", sshSnapshot(t, "Ciphers -aes*-cbc,3des-cbc\n"), model.StatusPass, ""},
		{"wildcard matches weak", sshSnapshot(t, "Ciphers +arcfour*\n"), model.StatusFail, "arcfour256"},
		{"case-insensitive", sshSnapshot(t, "MACs HMAC-MD5\n"), model.StatusFail, ""},
	})
}

func TestWeakInList(t *testing.T) {
	weak := weakAlgorithms["ciphers"]
	if got := weakInList("aes128-ctr,,  ,!3des-cbc", weak); len(got) != 0 {
		t.Errorf("negated/empty entries flagged: %q", got)
	}
	if got := weakInList("[", weak); len(got) != 0 {
		t.Errorf("malformed pattern flagged: %q", got)
	}
}

func accountSnapshot(t *testing.T, passwd string, shadow *string, loginDefs string) *model.Snapshot {
	t.Helper()
	fsys := platformtest.NewFS().AddText("/etc/passwd", passwd)
	if shadow == nil {
		fsys.Add("/etc/shadow", platformtest.File{Err: fs.ErrPermission})
	} else {
		fsys.AddText("/etc/shadow", *shadow)
	}
	if loginDefs != "" {
		fsys.AddText("/etc/login.defs", loginDefs)
	}
	return &model.Snapshot{Accounts: accounts.Collect(fsys)}
}

func ptr(s string) *string { return &s }

const basePasswd = "root:x:0:0:root:/root:/bin/bash\n" +
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
	"sync:x:4:65534:sync:/bin:/bin/sync\n" +
	"alice:x:1000:1000::/home/alice:/bin/bash\n"

func TestAccountRules(t *testing.T) {
	runCases(t, "USER-001", []ruleCase{
		{"only root", accountSnapshot(t, basePasswd, nil, ""), model.StatusPass, ""},
		{"backdoor", accountSnapshot(t, basePasswd+"toor:x:0:0::/root:/bin/sh\n", nil, ""), model.StatusFail, "toor has UID 0"},
		{"parse warnings surface", accountSnapshot(t, basePasswd+"garbage\n", nil, ""), model.StatusPass, "note: passwd line 5"},
		{"not supported", &model.Snapshot{Accounts: model.Unavailable[model.Accounts](model.Unsupported, "windows")}, model.StatusSkip, ""},
	})
	runCases(t, "USER-002", []ruleCase{
		{"empty in passwd is conclusive without shadow", accountSnapshot(t, basePasswd+"bob::1001:1001::/home/bob:/bin/sh\n", nil, ""), model.StatusFail, "bob"},
		{"shadow unreadable", accountSnapshot(t, basePasswd, nil, ""), model.StatusSkip, "insufficient privileges"},
		{"shadow empty password", accountSnapshot(t, basePasswd, ptr("root:!:1::::::\nalice::1::::::\n"), ""), model.StatusFail, "alice"},
		{"shadow ok", accountSnapshot(t, basePasswd, ptr("root:!:1::::::\nalice:$6$x$y:1::::::\n"), ""), model.StatusPass, "2 shadow entries"},
	})
	runCases(t, "USER-003", []ruleCase{
		{"shadowed", accountSnapshot(t, basePasswd, nil, ""), model.StatusPass, ""},
		{"hash in passwd", accountSnapshot(t, basePasswd+"old:$1$abc$def:1002:1002::/home/old:/bin/sh\n", nil, ""), model.StatusFail, "old"},
	})
	runCases(t, "USER-004", []ruleCase{
		{"unique", accountSnapshot(t, basePasswd, nil, ""), model.StatusPass, ""},
		{"duplicate", accountSnapshot(t, basePasswd+"alice2:x:1000:1000::/home/a2:/bin/bash\n", nil, ""), model.StatusFail, "UID 1000 is shared by alice, alice2"},
	})
	runCases(t, "USER-005", []ruleCase{
		{"conventional", accountSnapshot(t, basePasswd, nil, ""), model.StatusPass, ""},
		{"service with bash", accountSnapshot(t, basePasswd+"postgres:x:114:120::/var/lib/postgresql:/bin/bash\n", nil, ""), model.StatusFail, "postgres (UID 114)"},
		{"empty shell", accountSnapshot(t, basePasswd+"svc:x:200:200::/:\n", nil, ""), model.StatusFail, "defaults to /bin/sh"},
		{"UID_MIN from login.defs", accountSnapshot(t, basePasswd+"legacyuser:x:600:600::/home/l:/bin/bash\n", nil, "UID_MIN 500\n"), model.StatusPass, "UID < 500"},
	})
}

func fwSnapshot(elevated bool, providers ...model.FirewallProvider) *model.Snapshot {
	return &model.Snapshot{
		Host:     model.Host{Elevated: elevated},
		Firewall: model.CollectedSection(model.Firewall{Providers: providers}),
	}
}

func TestFirewallRule(t *testing.T) {
	nftUnknown := model.FirewallProvider{Name: "nftables kernel ruleset", State: model.FirewallUnknown, Evidence: []string{"requires root"}}
	nftOn := model.FirewallProvider{Name: "nftables kernel ruleset", State: model.FirewallEnabled, RuntimeVerified: true, Authoritative: true}
	nftOff := model.FirewallProvider{Name: "nftables kernel ruleset", State: model.FirewallDisabled, RuntimeVerified: true, Authoritative: true}
	ufwConfigOn := model.FirewallProvider{Name: "ufw", State: model.FirewallEnabled}
	firewalldOff := model.FirewallProvider{Name: "firewalld", State: model.FirewallDisabled, RuntimeVerified: true}
	firewalldOn := model.FirewallProvider{Name: "firewalld", State: model.FirewallEnabled, RuntimeVerified: true}

	runCases(t, "FW-001", []ruleCase{
		{"kernel ruleset filters", fwSnapshot(true, nftOn), model.StatusPass, ""},
		{"kernel ruleset empty", fwSnapshot(true, nftOff), model.StatusFail, ""},
		{"config intent only is not proof", fwSnapshot(false, nftUnknown, ufwConfigOn), model.StatusSkip, "without elevated privileges"},
		{"firewalld running without root", fwSnapshot(false, nftUnknown, firewalldOn), model.StatusPass, ""},
		{"non-authoritative disabled is not a failure", fwSnapshot(true, model.FirewallProvider{Name: "nftables kernel ruleset", State: model.FirewallUnknown}, firewalldOff), model.StatusSkip, ""},
		{"unsupported", &model.Snapshot{Firewall: model.Unavailable[model.Firewall](model.Unsupported, "darwin")}, model.StatusSkip, ""},
	})
}

func filesSnapshot(entries ...model.FileEntry) *model.Snapshot {
	return &model.Snapshot{Files: model.CollectedSection(entries), Host: model.Host{Elevated: false}}
}

func entry(path string, mode fs.FileMode, uid int64) model.FileEntry {
	return model.FileEntry{Path: path, Exists: true, Mode: mode, ModeString: mode.String(), UID: uid, GID: 0}
}

func TestFileRules(t *testing.T) {
	runCases(t, "FILE-001", []ruleCase{
		{"debian 0640", filesSnapshot(entry("/etc/shadow", 0o640, 0)), model.StatusPass, ""},
		{"rhel 0000", filesSnapshot(entry("/etc/shadow", 0, 0)), model.StatusPass, ""},
		{"world-readable", filesSnapshot(entry("/etc/shadow", 0o644, 0)), model.StatusFail, "0004"},
		{"wrong owner", filesSnapshot(entry("/etc/shadow", 0o640, 1000)), model.StatusFail, "uid 1000"},
		{"missing", filesSnapshot(model.FileEntry{Path: "/etc/shadow", UID: -1, GID: -1}), model.StatusSkip, ""},
		{"stat error unprivileged", filesSnapshot(model.FileEntry{Path: "/etc/shadow", Error: "permission denied", UID: -1}), model.StatusSkip, ""},
		{"not collected", filesSnapshot(), model.StatusError, "out of sync"},
		{"ownership unknown", filesSnapshot(entry("/etc/shadow", 0o640, -1)), model.StatusSkip, ""},
	})
	runCases(t, "FILE-003", []ruleCase{
		{"0644", filesSnapshot(entry("/etc/passwd", 0o644, 0)), model.StatusPass, ""},
		{"group-writable", filesSnapshot(entry("/etc/passwd", 0o664, 0)), model.StatusFail, ""},
		{"symlink noted", filesSnapshot(model.FileEntry{Path: "/etc/passwd", Exists: true, IsSymlink: true, Mode: 0o644, UID: 0}), model.StatusPass, "symlink"},
	})
	runCases(t, "FILE-007", []ruleCase{
		{"sticky", filesSnapshot(entry("/tmp", fs.ModeDir|fs.ModeSticky|0o777, 0), entry("/var/tmp", fs.ModeDir|fs.ModeSticky|0o777, 0)), model.StatusPass, ""},
		{"var tmp not sticky", filesSnapshot(entry("/tmp", fs.ModeDir|fs.ModeSticky|0o777, 0), entry("/var/tmp", fs.ModeDir|0o777, 0)), model.StatusFail, "/var/tmp"},
		{"not world-writable", filesSnapshot(entry("/tmp", fs.ModeDir|0o755, 0)), model.StatusPass, ""},
		{"none present", filesSnapshot(), model.StatusSkip, ""},
	})
}
