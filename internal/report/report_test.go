package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/engine"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

func TestSanitize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"PermitRootLogin yes", "PermitRootLogin yes"},
		{"tab\tkept", "tab\tkept"},
		{"unicode ok: Grüße, 日本", "unicode ok: Grüße, 日本"},
		{"\x1b[2J\x1b[31mred", `\x1b[2J\x1b[31mred`},
		{"line\nbreak\rreturn", `line\x0abreak\x0dreturn`},
		{"bell\a del\x7f", `bell\x07 del\x7f`},
		{"c1 " + string(rune(0x9b)) + " csi", `c1 \x9b csi`},
		{"invalid \xff utf8", `invalid \xff utf8`},
		{"bidi " + string(rune(0x202e)) + "evil" + string(rune(0x202c)), "bidi " + uesc("202e") + "evil" + uesc("202c")},
		{"isolate " + string(rune(0x2066)) + "x" + string(rune(0x2069)), "isolate " + uesc("2066") + "x" + uesc("2069")},
	}
	for _, tt := range tests {
		if got := Sanitize(tt.in); got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func sampleReport() Report {
	score := 50
	snap := &model.Snapshot{
		CollectedAt: time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC),
		Host:        model.Host{OS: "linux", Arch: "arm64", Hostname: "web-1", PrettyName: "Debian GNU/Linux 12"},
	}
	res := engine.Result{
		Findings: []model.Finding{
			{
				RuleID: "SSH-001", Title: "Root login", Severity: model.SeverityHigh, DefaultSeverity: model.SeverityHigh,
				Status: model.StatusFail, Message: "root login enabled",
				Evidence:          []string{"Banner \x1b]0;pwned\x07 (/etc/ssh/sshd_config:3)"},
				SeverityRationale: "because", Remediation: "fix it", References: []string{"https://man.openbsd.org/sshd_config"},
			},
			{RuleID: "USER-001", Title: "UID 0", Severity: model.SeverityCritical, DefaultSeverity: model.SeverityCritical,
				Status: model.StatusPass, Message: "ok", Evidence: []string{"3 accounts inspected"}},
			{RuleID: "FILE-001", Title: "shadow", Severity: model.SeverityHigh, DefaultSeverity: model.SeverityHigh,
				Status: model.StatusSkip, Message: "insufficient privileges"},
		},
		Summary: engine.Summary{Selected: 3, Evaluated: 2, Pass: 1, Fail: 1, Skip: 1, Score: &score,
			FailedBySeverity: map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
	}
	return New(snap, res, baseline.Default(), "v1.2.3")
}

func TestWriteTextEscapesUntrustedContent(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("raw control characters reached the terminal output:\n%q", out)
	}
	for _, want := range []string{
		`Banner \x1b]0;pwned\x07`,
		"Score:       50/100 over 2 of 3 selected rules",
		"Host:        web-1 (Debian GNU/Linux 12, linux/arm64)",
		"Failed checks (1)",
		"[HIGH] SSH-001  Root login",
		"Skipped checks (1)",
		"Passed checks (1)",
		"    - 3 accounts inspected",
		"Note: The audit did not run with elevated privileges",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q\n%s", want, out)
		}
	}
	if strings.Index(out, "Failed checks") > strings.Index(out, "Passed checks") {
		t.Error("failures must be listed before passes")
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"schema_version", "tool", "generated_at", "host", "baseline", "summary", "score_method", "findings"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON report missing %q", key)
		}
	}
	if bytes.Contains(buf.Bytes(), []byte{0x1b}) {
		t.Error("JSON must escape control characters")
	}
	findings := decoded["findings"].([]any)
	first := findings[0].(map[string]any)
	if first["severity"] != "HIGH" || first["status"] != "FAIL" {
		t.Errorf("severity/status must serialize as names: %v", first)
	}
}

func TestNewWithoutFindingsEmitsEmptyArray(t *testing.T) {
	r := New(&model.Snapshot{Host: model.Host{Elevated: true}}, engine.Result{}, baseline.Default(), "dev")
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) || strings.Contains(buf.String(), `"notes"`) {
		t.Errorf("unexpected JSON:\n%s", buf.String())
	}
	if err := WriteText(&buf, r); err != nil || !strings.Contains(buf.String(), "Score:       n/a") {
		t.Errorf("text report without evaluated rules: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, bytes.ErrTooLarge }

func TestWriteErrorsPropagate(t *testing.T) {
	if err := WriteText(failingWriter{}, sampleReport()); err == nil {
		t.Error("WriteText must return write errors")
	}
	if err := WriteJSON(failingWriter{}, sampleReport()); err == nil {
		t.Error("WriteJSON must return write errors")
	}
}

// uesc returns the literal text backslash-u followed by hex.
func uesc(hex string) string { return "\\" + "u" + hex }
