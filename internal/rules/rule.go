// Package rules defines the rule type and the built-in rule catalog. Rules
// are pure functions of a model.Snapshot: they never touch the operating
// system, which keeps them deterministic and testable on any platform.
package rules

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

// Rule is one baseline check.
type Rule struct {
	ID          string
	Title       string
	Description string
	Category    model.Category
	Severity    model.Severity
	// SeverityRationale explains why the rule has its default severity.
	SeverityRationale string
	// Platforms lists operating systems (GOOS values) where the rule can
	// produce PASS or FAIL. On other platforms it returns SKIP.
	Platforms   []string
	Remediation string
	References  []string
	Check       func(*model.Snapshot) Result
}

// Result is the outcome of a Check.
type Result struct {
	Status   model.Status
	Message  string
	Evidence []string
}

// Pass returns a PASS result.
func Pass(message string, evidence ...string) Result {
	return Result{Status: model.StatusPass, Message: message, Evidence: evidence}
}

// Fail returns a FAIL result.
func Fail(message string, evidence ...string) Result {
	return Result{Status: model.StatusFail, Message: message, Evidence: evidence}
}

// Skip returns a SKIP result.
func Skip(message string, evidence ...string) Result {
	return Result{Status: model.StatusSkip, Message: message, Evidence: evidence}
}

// Error returns an ERROR result.
func Error(message string, evidence ...string) Result {
	return Result{Status: model.StatusError, Message: message, Evidence: evidence}
}

// unavailable converts a non-collected section into SKIP or ERROR. It
// returns ok=false when the section holds usable data.
func unavailable[T any](what string, sec model.Section[T]) (Result, bool) {
	detail := sec.Detail
	if detail == "" {
		detail = string(sec.Status)
	}
	switch sec.Status {
	case model.Collected:
		return Result{}, false
	case model.Unsupported:
		return Skip(what + " is not supported on this platform: " + detail), true
	case model.NotFound:
		return Skip(what + " not present: " + detail), true
	case model.PermissionDenied:
		return Skip("insufficient privileges to read " + what + ": " + detail), true
	case model.Failed:
		return Error("collecting "+what+" failed: "+detail, sec.Warnings...), true
	default:
		return Error(fmt.Sprintf("%s has unknown collection status %q", what, sec.Status)), true
	}
}

var idPattern = regexp.MustCompile(`^[A-Z]+-[0-9]{3}$`)

// Validate checks catalog invariants: unique well-formed IDs and complete
// metadata. It is enforced by tests and at startup.
func Validate(rules []Rule) error {
	seen := map[string]bool{}
	var errs []error
	for _, r := range rules {
		if !idPattern.MatchString(r.ID) {
			errs = append(errs, fmt.Errorf("rule %q: ID must match %s", r.ID, idPattern))
		}
		if seen[r.ID] {
			errs = append(errs, fmt.Errorf("rule %q: duplicate ID", r.ID))
		}
		seen[r.ID] = true
		if r.Title == "" || r.Description == "" || r.Remediation == "" || r.SeverityRationale == "" || r.Category == "" {
			errs = append(errs, fmt.Errorf("rule %q: missing metadata", r.ID))
		}
		if !r.Severity.Valid() {
			errs = append(errs, fmt.Errorf("rule %q: invalid severity", r.ID))
		}
		if r.Check == nil {
			errs = append(errs, fmt.Errorf("rule %q: no check function", r.ID))
		}
		if len(r.Platforms) == 0 {
			errs = append(errs, fmt.Errorf("rule %q: no platforms listed", r.ID))
		}
		for _, ref := range r.References {
			u, err := url.Parse(ref)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				errs = append(errs, fmt.Errorf("rule %q: reference %q must be an https URL", r.ID, ref))
			}
		}
	}
	return errors.Join(errs...)
}
