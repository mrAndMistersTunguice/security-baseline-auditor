// Package integration runs the complete pipeline (collectors, rule engine,
// reporting, CLI) against fixture Linux systems. The fixtures are served
// through the in-memory platform fake, so these tests run on any OS.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/cli"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/engine"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform/platformtest"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/report"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/rules"
)

var update = flag.Bool("update", false, "rewrite golden files")

type fileMeta struct {
	mode fs.FileMode
	uid  int64
}

// loadHost builds a fake Linux system from tests/testdata/<name>.
func loadHost(t *testing.T, name string, meta map[string]fileMeta) platform.Env {
	t.Helper()
	root := filepath.Join("..", "testdata", name)
	fsys := platformtest.NewFS()
	for _, top := range []string{"etc", "proc"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			fsys.Add("/"+filepath.ToSlash(rel), platformtest.File{Data: data, Mode: 0o644})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Apply ownership and permissions; paths that are not fixture files
	// (directories, sudoers) are added as metadata-only entries.
	for p, m := range meta {
		data, _ := fsys.ReadFile(p, 1<<20)
		fsys.Add(p, platformtest.File{Data: data, Mode: m.mode, UID: m.uid})
	}

	ruleset, err := os.ReadFile(filepath.Join(root, "nft-ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	fsys.Add("/usr/sbin/nft", platformtest.File{Mode: 0o755})
	runner := &platformtest.Runner{Outputs: map[string]platformtest.Output{
		"/usr/sbin/nft -j list ruleset": {Stdout: ruleset},
	}}
	return platform.Env{GOOS: "linux", FS: fsys, Runner: runner, Elevated: true}
}

func collect(t *testing.T, env platform.Env) *model.Snapshot {
	t.Helper()
	snap := collector.Collect(context.Background(), env)
	// Make report output deterministic.
	snap.Host.Hostname = "fixture-host"
	snap.Host.Arch = "amd64"
	snap.CollectedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return snap
}

var hardenedMeta = map[string]fileMeta{
	"/etc/shadow":          {0o000, 0},
	"/etc/gshadow":         {0o000, 0},
	"/etc/passwd":          {0o644, 0},
	"/etc/group":           {0o644, 0},
	"/etc/sudoers":         {0o440, 0},
	"/etc/ssh/sshd_config": {0o600, 0},
	"/tmp":                 {fs.ModeDir | fs.ModeSticky | 0o777, 0},
	"/var/tmp":             {fs.ModeDir | fs.ModeSticky | 0o777, 0},
}

var insecureMeta = map[string]fileMeta{
	"/etc/shadow":          {0o644, 0},
	"/etc/passwd":          {0o666, 0},
	"/etc/group":           {0o644, 0},
	"/etc/sudoers":         {0o440, 1000},
	"/etc/ssh/sshd_config": {0o644, 0},
	"/tmp":                 {fs.ModeDir | fs.ModeSticky | 0o777, 0},
	"/var/tmp":             {fs.ModeDir | 0o777, 0},
}

func statuses(res engine.Result) map[string]model.Status {
	out := map[string]model.Status{}
	for _, f := range res.Findings {
		out[f.RuleID] = f.Status
	}
	return out
}

func TestHardenedHostPassesEveryRule(t *testing.T) {
	snap := collect(t, loadHost(t, "hardened", hardenedMeta))
	res := engine.Run(snap, rules.Builtin(), baseline.Default())
	for _, f := range res.Findings {
		if f.Status != model.StatusPass {
			t.Errorf("%s: %s (%s) evidence=%q", f.RuleID, f.Status, f.Message, f.Evidence)
		}
	}
	if res.Summary.Score == nil || *res.Summary.Score != 100 {
		t.Errorf("score = %d, want 100", derefScore(res.Summary.Score))
	}
}

func TestInsecureHostFindings(t *testing.T) {
	snap := collect(t, loadHost(t, "insecure", insecureMeta))
	res := engine.Run(snap, rules.Builtin(), baseline.Default())

	want := map[string]model.Status{
		"SSH-001": model.StatusFail, "SSH-002": model.StatusFail, "SSH-003": model.StatusFail,
		"SSH-004": model.StatusFail, "SSH-005": model.StatusPass, "SSH-006": model.StatusFail,
		"SSH-007": model.StatusFail, "SSH-008": model.StatusFail, "SSH-009": model.StatusFail,
		"USER-001": model.StatusFail, "USER-002": model.StatusFail, "USER-003": model.StatusPass,
		"USER-004": model.StatusFail, "USER-005": model.StatusFail,
		"FW-001":   model.StatusFail,
		"FILE-001": model.StatusFail, "FILE-002": model.StatusSkip, "FILE-003": model.StatusFail,
		"FILE-004": model.StatusPass, "FILE-005": model.StatusFail, "FILE-006": model.StatusPass,
		"FILE-007": model.StatusFail,
	}
	got := statuses(res)
	if len(got) != len(want) {
		t.Errorf("got %d findings, want %d", len(got), len(want))
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %s, want %s", id, got[id], w)
		}
	}

	var buf bytes.Buffer
	if err := report.WriteText(&buf, report.New(snap, res, baseline.Default(), "test")); err != nil {
		t.Fatal(err)
	}
	golden(t, filepath.Join("..", "testdata", "insecure-report.golden.txt"), buf.Bytes())

	// No secret material from the fixtures may reach the report.
	if bytes.Contains(buf.Bytes(), []byte("NotARealHash")) {
		t.Fatal("password hash leaked into report")
	}
}

func TestUnprivilegedAuditSkipsInsteadOfGuessing(t *testing.T) {
	env := loadHost(t, "insecure", insecureMeta)
	env.Elevated = false
	env.FS.(*platformtest.FS).Add("/etc/shadow", platformtest.File{Mode: 0o640, Err: fs.ErrPermission})
	snap := collect(t, env)
	got := statuses(engine.Run(snap, rules.Builtin(), baseline.Default()))

	// Empty password in world-readable /etc/passwd is still conclusive.
	if got["USER-002"] != model.StatusFail {
		t.Errorf("USER-002 = %s, want FAIL", got["USER-002"])
	}
	// The kernel ruleset is not inspected without root, and ufw.conf is
	// not proof, so the firewall rule must not PASS or FAIL.
	if got["FW-001"] != model.StatusSkip {
		t.Errorf("FW-001 = %s, want SKIP", got["FW-001"])
	}
	if calls := env.Runner.(*platformtest.Runner).Calls; len(calls) != 0 {
		t.Errorf("unprivileged audit executed commands: %q", calls)
	}
}

func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./tests/... -update to create it)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("output differs from %s; run with -update and review the diff.\n--- got ---\n%s", path, got)
	}
}

// newApp returns a CLI app that audits the given fixture host.
func newApp(t *testing.T, env platform.Env) (*cli.App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := &cli.App{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Env:     env,
		Catalog: rules.Builtin(),
		Collect: func(ctx context.Context, e platform.Env) *model.Snapshot { return collect(t, e) },
	}
	return app, &stdout, &stderr
}

func TestCLIExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"insecure default threshold", "insecure", []string{"audit"}, cli.ExitFindings, ""},
		{"insecure report-only", "insecure", []string{"audit", "--fail-on", "none"}, cli.ExitOK, ""},
		{"insecure only critical", "insecure", []string{"audit", "--fail-on", "critical", "--format", "json"}, cli.ExitFindings, ""},
		{"hardened", "hardened", []string{"audit"}, cli.ExitOK, ""},
		{"bad format", "hardened", []string{"audit", "--format", "yaml"}, cli.ExitUsage, "invalid --format"},
		{"bad threshold", "hardened", []string{"audit", "--fail-on", "severe"}, cli.ExitUsage, "invalid --fail-on"},
		{"unknown flag", "hardened", []string{"audit", "--nope"}, cli.ExitUsage, "flag provided but not defined"},
		{"stray argument", "hardened", []string{"audit", "extra"}, cli.ExitUsage, "unexpected argument"},
		{"missing config", "hardened", []string{"audit", "--config", "/nonexistent.yaml"}, cli.ExitUsage, "cannot read baseline"},
		{"unknown command", "hardened", []string{"scan"}, cli.ExitUsage, "unknown command"},
		{"no command", "hardened", nil, cli.ExitUsage, "Usage"},
		{"rules without list", "hardened", []string{"rules"}, cli.ExitUsage, "rules list"},
		{"help", "hardened", []string{"--help"}, cli.ExitOK, ""},
		{"audit help", "hardened", []string{"audit", "-h"}, cli.ExitOK, ""},
		{"version", "hardened", []string{"--version"}, cli.ExitOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := hardenedMeta
			if tt.host == "insecure" {
				meta = insecureMeta
			}
			app, _, stderr := newApp(t, loadHost(t, tt.host, meta))
			code := app.Run(context.Background(), tt.args)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr %q)", code, tt.wantCode, stderr.String())
			}
			if tt.wantErr != "" && !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tt.wantErr)
			}
			if strings.Contains(stderr.String(), "goroutine ") {
				t.Error("stack trace printed")
			}
		})
	}
}

func TestCLIThresholdIgnoresLowerSeverities(t *testing.T) {
	// Only the LOW-severity SSH-008 fails in this configuration.
	env := loadHost(t, "hardened", hardenedMeta)
	env.FS.(*platformtest.FS).AddText("/etc/ssh/sshd_config.d/00-hardening.conf",
		"PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMaxAuthTries 3\nX11Forwarding yes\n")
	for threshold, want := range map[string]int{"low": cli.ExitFindings, "medium": cli.ExitOK} {
		app, _, _ := newApp(t, env)
		if code := app.Run(context.Background(), []string{"audit", "--fail-on", threshold}); code != want {
			t.Errorf("--fail-on %s: exit %d, want %d", threshold, code, want)
		}
	}
}

func TestCLIJSONReport(t *testing.T) {
	app, stdout, _ := newApp(t, loadHost(t, "insecure", insecureMeta))
	if code := app.Run(context.Background(), []string{"audit", "--format", "json"}); code != cli.ExitFindings {
		t.Fatalf("exit = %d", code)
	}
	var rep report.Report
	dec := json.NewDecoder(stdout)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("report is not valid JSON for the Report schema: %v", err)
	}
	if rep.SchemaVersion != report.SchemaVersion || rep.Summary.Selected != len(rules.Builtin()) || rep.Host.DistroID != "ubuntu" {
		t.Errorf("report header = %+v / %+v", rep.Host, rep.Summary)
	}
	if rep.Findings[0].Status != model.StatusFail || rep.Findings[0].Severity != model.SeverityCritical {
		t.Errorf("first finding should be the most severe failure: %+v", rep.Findings[0])
	}
}

func TestCLIConfigBaseline(t *testing.T) {
	env := loadHost(t, "insecure", insecureMeta)
	env.FS.(*platformtest.FS).AddText("/baseline.yaml", `version: 1
name: ssh-only
rules: [SSH-001, SSH-008]
exclude:
  - rule: SSH-008
    reason: required by legacy tooling
severity_overrides:
  SSH-001: critical
`)
	app, stdout, stderr := newApp(t, env)
	code := app.Run(context.Background(), []string{"audit", "--config", "/baseline.yaml", "--format", "json"})
	if code != cli.ExitFindings {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	var rep report.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 2 || rep.Baseline.Name != "ssh-only" {
		t.Fatalf("findings = %d, baseline = %+v", len(rep.Findings), rep.Baseline)
	}
	for _, f := range rep.Findings {
		switch f.RuleID {
		case "SSH-001":
			if f.Severity != model.SeverityCritical || f.Status != model.StatusFail {
				t.Errorf("SSH-001 = %+v", f)
			}
		case "SSH-008":
			if f.Status != model.StatusSkip || !strings.Contains(f.Message, "legacy tooling") {
				t.Errorf("SSH-008 = %+v", f)
			}
		}
	}

	env.FS.(*platformtest.FS).AddText("/typo.yaml", "version: 1\nrules: [SSH-01]\n")
	app, _, stderr = newApp(t, env)
	if code := app.Run(context.Background(), []string{"audit", "--config", "/typo.yaml"}); code != cli.ExitUsage || !strings.Contains(stderr.String(), "SSH-01") {
		t.Fatalf("typo baseline: exit %d, stderr %q", code, stderr)
	}
}

func TestCLIRulesAndSnapshot(t *testing.T) {
	app, stdout, _ := newApp(t, loadHost(t, "insecure", insecureMeta))
	if code := app.Run(context.Background(), []string{"rules", "list", "--format", "json"}); code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var list []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil || len(list) != len(rules.Builtin()) {
		t.Fatalf("rules list: %v (%d entries)", err, len(list))
	}

	app, stdout, _ = newApp(t, loadHost(t, "insecure", insecureMeta))
	if code := app.Run(context.Background(), []string{"snapshot"}); code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if bytes.Contains(stdout.Bytes(), []byte("NotARealHash")) {
		t.Fatal("snapshot leaked a password hash")
	}
	var snap model.Snapshot
	if err := json.Unmarshal(stdout.Bytes(), &snap); err != nil || snap.Accounts.Status != model.Collected {
		t.Fatalf("snapshot: %v", err)
	}
}

func TestCLIRecoversFromPanics(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &cli.App{
		Stdout: &stdout, Stderr: &stderr, Catalog: rules.Builtin(),
		Collect: func(context.Context, platform.Env) *model.Snapshot { panic("collector bug") },
	}
	if code := app.Run(context.Background(), []string{"audit"}); code != cli.ExitRuntime {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "internal error: collector bug") || strings.Contains(stderr.String(), "goroutine") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func derefScore(s *int) int {
	if s == nil {
		return -1
	}
	return *s
}
