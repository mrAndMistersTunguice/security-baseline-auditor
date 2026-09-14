package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

// WriteText writes a human-readable report. Every string that may come
// from the audited system is passed through Sanitize, so crafted file
// content cannot inject terminal escape sequences.
func WriteText(w io.Writer, r Report) error {
	bw := bufio.NewWriter(w)
	p := func(format string, args ...any) { fmt.Fprintf(bw, format, args...) }

	p("Security Baseline Audit\n")
	p("=======================\n\n")
	p("Host:        %s\n", Sanitize(hostLine(r.Host)))
	if r.Host.Elevated {
		p("Privileges:  elevated\n")
	} else {
		p("Privileges:  not elevated\n")
	}
	p("Baseline:    %s (%s)\n", Sanitize(r.Baseline.Name), Sanitize(r.Baseline.Source))
	p("Tool:        %s %s\n", r.Tool.Name, Sanitize(r.Tool.Version))
	p("Time:        %s\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05 MST"))

	s := r.Summary
	p("Summary\n-------\n")
	p("Rules:       %d selected: %d PASS, %d FAIL, %d SKIP, %d ERROR\n", s.Selected, s.Pass, s.Fail, s.Skip, s.Error)
	p("Failed:      CRITICAL %d | HIGH %d | MEDIUM %d | LOW %d | INFO %d\n",
		s.FailedBySeverity["CRITICAL"], s.FailedBySeverity["HIGH"], s.FailedBySeverity["MEDIUM"],
		s.FailedBySeverity["LOW"], s.FailedBySeverity["INFO"])
	if s.Score != nil {
		p("Score:       %d/100 over %d of %d selected rules\n", *s.Score, s.Evaluated, s.Selected)
	} else {
		p("Score:       n/a (no rule could be evaluated)\n")
	}
	p("             (%s)\n", r.ScoreMethod)
	for _, n := range r.Notes {
		p("\nNote: %s\n", Sanitize(n))
	}

	// FAIL and ERROR findings are shown in full; SKIP and PASS compactly,
	// with their evidence.
	section := func(title string, status model.Status, full bool) {
		var items []model.Finding
		for _, f := range r.Findings {
			if f.Status == status {
				items = append(items, f)
			}
		}
		if len(items) == 0 {
			return
		}
		heading := fmt.Sprintf("%s (%d)", title, len(items))
		p("\n%s\n%s\n", heading, strings.Repeat("-", len(heading)))
		for _, f := range items {
			if full {
				writeDetailed(p, f)
				continue
			}
			p("[%s] %s  %s\n", f.Severity, f.RuleID, Sanitize(f.Title))
			p("    %s\n", Sanitize(f.Message))
			for _, e := range f.Evidence {
				p("    - %s\n", Sanitize(e))
			}
		}
	}
	section("Failed checks", model.StatusFail, true)
	section("Errors", model.StatusError, true)
	section("Skipped checks", model.StatusSkip, false)
	section("Passed checks", model.StatusPass, false)

	return bw.Flush()
}

func writeDetailed(p func(string, ...any), f model.Finding) {
	p("\n[%s] %s  %s\n", f.Severity, f.RuleID, Sanitize(f.Title))
	p("  Result:      %s\n", Sanitize(f.Message))
	if len(f.Evidence) > 0 {
		p("  Evidence:\n")
		for _, e := range f.Evidence {
			p("    - %s\n", Sanitize(e))
		}
	}
	p("  Severity:    %s. %s\n", f.Severity, Sanitize(f.SeverityRationale))
	p("  Remediation: %s\n", Sanitize(f.Remediation))
	for _, ref := range f.References {
		p("  Reference:   %s\n", Sanitize(ref))
	}
}

func hostLine(h model.Host) string {
	name := h.Hostname
	if name == "" {
		name = "(unknown host)"
	}
	var parts []string
	if h.PrettyName != "" {
		parts = append(parts, h.PrettyName)
	}
	parts = append(parts, h.OS+"/"+h.Arch)
	if h.KernelVersion != "" && h.OS != "windows" {
		parts = append(parts, "kernel "+h.KernelVersion)
	}
	return fmt.Sprintf("%s (%s)", name, strings.Join(parts, ", "))
}

// Sanitize escapes control characters, invalid UTF-8 and Unicode
// bidirectional formatting characters so that untrusted text renders
// literally in a terminal.
func Sanitize(s string) string {
	if isSafe(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\t':
			b.WriteRune(r)
		case unsafeRune(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func isSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != '\t' && unsafeRune(r) {
			return false
		}
	}
	return true
}

func unsafeRune(r rune) bool {
	if unicode.IsControl(r) {
		return true
	}
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C:
		return true
	}
	return false
}
