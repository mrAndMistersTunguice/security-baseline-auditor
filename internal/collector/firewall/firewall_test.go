package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAnalyzeRuleset(t *testing.T) {
	tests := []struct {
		fixture       string
		wantChains    int
		wantFiltering bool
		wantReason    string
	}{
		{"nft-firewalld.json", 1, true, "reject rule"},
		{"nft-iptables-nft-policy-drop.json", 1, true, "policy drop"},
		{"nft-accept-only.json", 1, false, ""},
		{"nft-vmap-in-jumped-chain.json", 1, true, "drop rule in chain services"},
		{"nft-dormant.json", 0, false, ""},
		{"nft-jump-loop.json", 1, false, ""},
		{"nft-empty.json", 0, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			res, err := AnalyzeRuleset(fixture(t, tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if res.InputChains != tt.wantChains {
				t.Errorf("input chains = %d, want %d", res.InputChains, tt.wantChains)
			}
			if got := len(res.Filtering) > 0; got != tt.wantFiltering {
				t.Fatalf("filtering = %v (%q), want %v", got, res.Filtering, tt.wantFiltering)
			}
			if tt.wantReason != "" && !strings.Contains(strings.Join(res.Filtering, ";"), tt.wantReason) {
				t.Errorf("reasons %q do not mention %q", res.Filtering, tt.wantReason)
			}
		})
	}
}

func TestAnalyzeRulesetMalformed(t *testing.T) {
	inputs := map[string]string{
		"empty":               "",
		"not json":            "table inet filter {",
		"wrong top-level":     `{"tables": []}`,
		"chain wrong type":    `{"nftables": [{"chain": "oops"}]}`,
		"truncated":           `{"nftables": [{"chain": {"family": "inet"`,
		"deeply nested array": `{"nftables": [` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `]}`,
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			if _, err := AnalyzeRuleset([]byte(input)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestScanExprDepthLimit(t *testing.T) {
	var v any = map[string]any{"drop": nil}
	for range maxExprDepth + 10 {
		v = []any{v}
	}
	if verdict, _ := scanExpr(v, 0); verdict != "" {
		t.Fatal("verdict beyond the depth limit must not be reported")
	}
}

func TestParseUFWEnabled(t *testing.T) {
	tests := []struct {
		input          string
		enabled, found bool
	}{
		{"# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n", true, true},
		{"ENABLED=no\n", false, true},
		{"ENABLED=\"yes\"\n", true, true},
		{"LOGLEVEL=low\n", false, false},
	}
	for _, tt := range tests {
		enabled, found := ParseUFWEnabled([]byte(tt.input))
		if enabled != tt.enabled || found != tt.found {
			t.Errorf("ParseUFWEnabled(%q) = %v,%v", tt.input, enabled, found)
		}
	}
}

func procFS() *platformtest.FS {
	return platformtest.NewFS().
		AddText("/proc/1/comm", "systemd\n").
		AddText("/proc/1/status", "Name:\tsystemd\nUid:\t0\t0\t0\t0\n").
		AddText("/proc/self/comm", "sba\n")
}

func providerByName(fw model.Firewall, name string) (model.FirewallProvider, bool) {
	for _, p := range fw.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return model.FirewallProvider{}, false
}

func TestCollectLinux(t *testing.T) {
	const nftKey = "/usr/sbin/nft -j list ruleset"

	t.Run("unprivileged: kernel ruleset not inspected", func(t *testing.T) {
		runner := &platformtest.Runner{}
		env := platform.Env{GOOS: "linux", FS: procFS().AddText("/etc/ufw/ufw.conf", "ENABLED=yes\n"), Runner: runner}
		sec := CollectLinux(context.Background(), env)
		if len(runner.Calls) != 0 {
			t.Fatalf("unprivileged collection must not execute commands, ran %q", runner.Calls)
		}
		nft, _ := providerByName(sec.Data, "nftables kernel ruleset")
		if nft.State != model.FirewallUnknown || nft.Authoritative {
			t.Errorf("nft provider = %+v", nft)
		}
		ufw, ok := providerByName(sec.Data, "ufw")
		if !ok || ufw.State != model.FirewallEnabled || ufw.RuntimeVerified {
			t.Errorf("ufw provider = %+v", ufw)
		}
	})

	t.Run("root: ruleset with filtering", func(t *testing.T) {
		fsys := procFS().AddText("/usr/sbin/nft", "")
		runner := &platformtest.Runner{Outputs: map[string]platformtest.Output{nftKey: {Stdout: fixture(t, "nft-firewalld.json")}}}
		sec := CollectLinux(context.Background(), platform.Env{GOOS: "linux", FS: fsys, Runner: runner, Elevated: true})
		nft, _ := providerByName(sec.Data, "nftables kernel ruleset")
		if nft.State != model.FirewallEnabled || !nft.Authoritative || !nft.RuntimeVerified {
			t.Errorf("nft provider = %+v", nft)
		}
	})

	t.Run("root: no filtering and no legacy tables is conclusive", func(t *testing.T) {
		fsys := procFS().AddText("/usr/sbin/nft", "")
		runner := &platformtest.Runner{Outputs: map[string]platformtest.Output{nftKey: {Stdout: fixture(t, "nft-accept-only.json")}}}
		sec := CollectLinux(context.Background(), platform.Env{GOOS: "linux", FS: fsys, Runner: runner, Elevated: true})
		nft, _ := providerByName(sec.Data, "nftables kernel ruleset")
		if nft.State != model.FirewallDisabled || !nft.Authoritative {
			t.Errorf("nft provider = %+v", nft)
		}
	})

	t.Run("root: legacy iptables tables make empty nft inconclusive", func(t *testing.T) {
		fsys := procFS().AddText("/usr/sbin/nft", "").AddText("/proc/net/ip_tables_names", "filter\nnat\n")
		runner := &platformtest.Runner{Outputs: map[string]platformtest.Output{nftKey: {Stdout: fixture(t, "nft-empty.json")}}}
		sec := CollectLinux(context.Background(), platform.Env{GOOS: "linux", FS: fsys, Runner: runner, Elevated: true})
		nft, _ := providerByName(sec.Data, "nftables kernel ruleset")
		if nft.State != model.FirewallUnknown || nft.Authoritative {
			t.Errorf("nft provider = %+v", nft)
		}
		if !strings.Contains(strings.Join(nft.Evidence, " "), "ip:filter") {
			t.Errorf("evidence should name legacy tables: %q", nft.Evidence)
		}
	})

	t.Run("root: nft fails", func(t *testing.T) {
		fsys := procFS().AddText("/sbin/nft", "")
		runner := &platformtest.Runner{Outputs: map[string]platformtest.Output{
			"/sbin/nft -j list ruleset": {Err: errors.New("exit status 1")},
		}}
		sec := CollectLinux(context.Background(), platform.Env{GOOS: "linux", FS: fsys, Runner: runner, Elevated: true})
		nft, _ := providerByName(sec.Data, "nftables kernel ruleset")
		if nft.State != model.FirewallUnknown || nft.Authoritative {
			t.Errorf("nft provider = %+v", nft)
		}
	})

	t.Run("root: nft not installed", func(t *testing.T) {
		runner := &platformtest.Runner{}
		sec := CollectLinux(context.Background(), platform.Env{GOOS: "linux", FS: procFS(), Runner: runner, Elevated: true})
		nft, _ := providerByName(sec.Data, "nftables kernel ruleset")
		if nft.State != model.FirewallUnknown || len(runner.Calls) != 0 {
			t.Errorf("nft provider = %+v calls=%q", nft, runner.Calls)
		}
	})
}

func TestFirewalldDetection(t *testing.T) {
	tests := []struct {
		name      string
		fs        *platformtest.FS
		elevated  bool
		wantFound bool
		wantState model.FirewallState
	}{
		{
			name: "running as root",
			fs: procFS().AddText("/proc/812/comm", "firewalld\n").
				AddText("/proc/812/status", "Name:\tfirewalld\nUid:\t0\t0\t0\t0\n"),
			wantFound: true, wantState: model.FirewallEnabled,
		},
		{
			name: "spoofed by unprivileged user",
			fs: procFS().AddText("/proc/4242/comm", "firewalld\n").
				AddText("/proc/4242/status", "Name:\tfirewalld\nUid:\t1000\t1000\t1000\t1000\n"),
			wantFound: false,
		},
		{
			name:      "installed, not running, root view",
			fs:        procFS().AddText(firewalldConf, "DefaultZone=public\n"),
			elevated:  true,
			wantFound: true, wantState: model.FirewallDisabled,
		},
		{
			name:      "installed, not running, unprivileged view",
			fs:        procFS().AddText(firewalldConf, "DefaultZone=public\n"),
			wantFound: true, wantState: model.FirewallUnknown,
		},
		{
			name:      "not installed",
			fs:        procFS(),
			wantFound: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, found, _ := firewalldProvider(platform.Env{FS: tt.fs, Elevated: tt.elevated})
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if found && p.State != tt.wantState {
				t.Errorf("state = %s, want %s", p.State, tt.wantState)
			}
			if p.Authoritative {
				t.Error("firewalld must never be authoritative")
			}
		})
	}
}

func u64(v uint64) *uint64 { return &v }

func TestEvaluateWindows(t *testing.T) {
	allOn := []WindowsProfile{
		{Name: "Domain", Local: u64(1)},
		{Name: "Private", Local: u64(1)},
		{Name: "Public", Local: u64(1)},
	}
	running := ServiceState{Known: true, Running: true}

	tests := []struct {
		name          string
		profiles      []WindowsProfile
		svc           ServiceState
		wantState     model.FirewallState
		authoritative bool
	}{
		{"all enabled", allOn, running, model.FirewallEnabled, true},
		{
			"public disabled locally",
			[]WindowsProfile{{Name: "Domain", Local: u64(1)}, {Name: "Private", Local: u64(1)}, {Name: "Public", Local: u64(0)}},
			running, model.FirewallDisabled, true,
		},
		{
			"group policy overrides local disable",
			[]WindowsProfile{{Name: "Domain", Local: u64(1)}, {Name: "Private", Local: u64(1)}, {Name: "Public", Local: u64(0), Policy: u64(1)}},
			running, model.FirewallEnabled, true,
		},
		{
			"group policy disables",
			[]WindowsProfile{{Name: "Domain", Local: u64(1), Policy: u64(0)}, {Name: "Private", Local: u64(1)}, {Name: "Public", Local: u64(1)}},
			running, model.FirewallDisabled, true,
		},
		{"service stopped", allOn, ServiceState{Known: true, Running: false, Detail: "stopped"}, model.FirewallDisabled, true},
		{"service unknown", allOn, ServiceState{Detail: "access denied"}, model.FirewallUnknown, false},
		{
			"value missing",
			[]WindowsProfile{{Name: "Domain", Local: u64(1)}, {Name: "Private"}, {Name: "Public", Local: u64(1)}},
			running, model.FirewallUnknown, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := EvaluateWindows(tt.profiles, tt.svc)
			if p.State != tt.wantState || p.Authoritative != tt.authoritative {
				t.Fatalf("got state=%s authoritative=%v evidence=%q", p.State, p.Authoritative, p.Evidence)
			}
			if len(p.Evidence) == 0 {
				t.Error("evidence must not be empty")
			}
		})
	}
}
