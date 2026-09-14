// Package engine evaluates rules against a snapshot according to a
// baseline and summarizes the findings.
package engine

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/rules"
)

// MaxEvidence caps evidence lines per finding so that a pathological system
// (for example thousands of duplicate UIDs) cannot produce unbounded output.
const MaxEvidence = 50

// Result is the outcome of an audit.
type Result struct {
	Findings []model.Finding `json:"findings"`
	Summary  Summary         `json:"summary"`
}

// Summary aggregates findings.
type Summary struct {
	Selected int `json:"selected"`
	// Evaluated counts findings with PASS or FAIL; the score covers only
	// these.
	Evaluated int `json:"evaluated"`
	Pass      int `json:"pass"`
	Fail      int `json:"fail"`
	Skip      int `json:"skip"`
	Error     int `json:"error"`
	// FailedBySeverity counts FAIL findings per severity name.
	FailedBySeverity map[string]int `json:"failed_by_severity"`
	// Score is nil when no rule produced PASS or FAIL.
	Score *int `json:"score"`
}

// SeverityWeights are the weights used by the score. See docs/scoring.md.
var SeverityWeights = map[model.Severity]int{
	model.SeverityInfo:     0,
	model.SeverityLow:      1,
	model.SeverityMedium:   2,
	model.SeverityHigh:     4,
	model.SeverityCritical: 8,
}

// Run evaluates the rules selected by b against snap.
func Run(snap *model.Snapshot, catalog []rules.Rule, b baseline.Baseline) Result {
	var res Result
	for _, r := range catalog {
		if len(b.Rules) > 0 && !slices.Contains(b.Rules, r.ID) {
			continue
		}
		res.Findings = append(res.Findings, evaluate(snap, r, b))
	}
	sortFindings(res.Findings)
	res.Summary = summarize(res.Findings)
	return res
}

func evaluate(snap *model.Snapshot, r rules.Rule, b baseline.Baseline) model.Finding {
	f := model.Finding{
		RuleID:            r.ID,
		Title:             r.Title,
		Description:       r.Description,
		Category:          r.Category,
		Severity:          r.Severity,
		DefaultSeverity:   r.Severity,
		SeverityRationale: r.SeverityRationale,
		Remediation:       r.Remediation,
		References:        slices.Clone(r.References),
	}
	if sev, ok := b.SeverityOverrides[r.ID]; ok {
		f.Severity = sev
		f.SeverityRationale = fmt.Sprintf("Severity overridden by baseline %q (default %s). Default rationale: %s",
			b.Name, r.Severity, r.SeverityRationale)
	}

	if reason, ok := b.Exclusions[r.ID]; ok {
		f.Status = model.StatusSkip
		f.Message = "excluded by baseline: " + reason
		return f
	}
	if snap.Host.OS != "" && !slices.Contains(r.Platforms, snap.Host.OS) {
		f.Status = model.StatusSkip
		f.Message = fmt.Sprintf("not applicable on %s (rule targets %s)", snap.Host.OS, strings.Join(r.Platforms, ", "))
		return f
	}

	out := safeCheck(snap, r)
	if !out.Status.Valid() {
		out = rules.Error(fmt.Sprintf("rule returned invalid status %q", out.Status))
	}
	f.Status = out.Status
	f.Message = out.Message
	f.Evidence = capEvidence(out.Evidence)
	return f
}

// safeCheck converts a panicking check into an ERROR finding so one buggy
// rule cannot abort the audit or produce a partial report.
func safeCheck(snap *model.Snapshot, r rules.Rule) (out rules.Result) {
	defer func() {
		if p := recover(); p != nil {
			out = rules.Error(fmt.Sprintf("internal error while evaluating rule: %v", p))
		}
	}()
	return r.Check(snap)
}

func capEvidence(ev []string) []string {
	if len(ev) <= MaxEvidence {
		return ev
	}
	out := slices.Clone(ev[:MaxEvidence])
	return append(out, fmt.Sprintf("... %d more evidence lines omitted", len(ev)-MaxEvidence))
}

var statusOrder = map[model.Status]int{
	model.StatusFail:  0,
	model.StatusError: 1,
	model.StatusSkip:  2,
	model.StatusPass:  3,
}

// sortFindings orders by status (FAIL, ERROR, SKIP, PASS), then severity
// (highest first), then rule ID, so output is deterministic.
func sortFindings(findings []model.Finding) {
	slices.SortStableFunc(findings, func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(statusOrder[a.Status], statusOrder[b.Status]),
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.RuleID, b.RuleID),
		)
	})
}

func summarize(findings []model.Finding) Summary {
	s := Summary{Selected: len(findings), FailedBySeverity: map[string]int{}}
	for _, sev := range model.AllSeverities() {
		s.FailedBySeverity[sev.String()] = 0
	}
	passWeight, totalWeight := 0, 0
	for _, f := range findings {
		switch f.Status {
		case model.StatusPass:
			s.Pass++
			passWeight += SeverityWeights[f.Severity]
			totalWeight += SeverityWeights[f.Severity]
		case model.StatusFail:
			s.Fail++
			s.FailedBySeverity[f.Severity.String()]++
			totalWeight += SeverityWeights[f.Severity]
		case model.StatusSkip:
			s.Skip++
		case model.StatusError:
			s.Error++
		}
	}
	s.Evaluated = s.Pass + s.Fail
	if totalWeight > 0 {
		score := int(math.Round(100 * float64(passWeight) / float64(totalWeight)))
		s.Score = &score
	}
	return s
}
