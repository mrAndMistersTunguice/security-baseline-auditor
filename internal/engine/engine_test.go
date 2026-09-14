package engine

import (
	"fmt"
	"testing"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/rules"
)

func fakeRule(id string, sev model.Severity, res rules.Result) rules.Rule {
	return rules.Rule{
		ID: id, Title: id, Description: "d", Category: model.CategorySSH, Severity: sev,
		SeverityRationale: "r", Remediation: "fix", Platforms: []string{"linux"},
		Check: func(*model.Snapshot) rules.Result { return res },
	}
}

func TestRunSortsAndSummarizes(t *testing.T) {
	catalog := []rules.Rule{
		fakeRule("A-001", model.SeverityLow, rules.Pass("ok")),
		fakeRule("A-002", model.SeverityCritical, rules.Fail("bad")),
		fakeRule("A-003", model.SeverityMedium, rules.Skip("n/a")),
		fakeRule("A-004", model.SeverityHigh, rules.Error("boom")),
		fakeRule("A-005", model.SeverityHigh, rules.Fail("bad")),
		fakeRule("A-006", model.SeverityHigh, rules.Pass("ok")),
	}
	res := Run(&model.Snapshot{}, catalog, baseline.Default())

	var order []string
	for _, f := range res.Findings {
		order = append(order, f.RuleID)
	}
	want := []string{"A-002", "A-005", "A-004", "A-003", "A-006", "A-001"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Errorf("order = %v, want %v", order, want)
	}

	s := res.Summary
	if s.Selected != 6 || s.Pass != 2 || s.Fail != 2 || s.Skip != 1 || s.Error != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.FailedBySeverity["CRITICAL"] != 1 || s.FailedBySeverity["HIGH"] != 1 || s.FailedBySeverity["INFO"] != 0 {
		t.Errorf("failed by severity = %v", s.FailedBySeverity)
	}
	// pass weight: LOW 1 + HIGH 4 = 5; total: 5 + CRITICAL 8 + HIGH 4 = 17.
	if s.Score == nil || *s.Score != 29 {
		t.Errorf("score = %v, want 29", s.Score)
	}
}

func TestScoreUndefinedWithoutEvaluatedRules(t *testing.T) {
	catalog := []rules.Rule{fakeRule("A-001", model.SeverityHigh, rules.Skip("no data"))}
	if s := Run(&model.Snapshot{}, catalog, baseline.Default()).Summary; s.Score != nil {
		t.Fatalf("score = %d, want nil", *s.Score)
	}
}

func TestBaselineSelectionExclusionAndOverride(t *testing.T) {
	catalog := []rules.Rule{
		fakeRule("A-001", model.SeverityLow, rules.Fail("bad")),
		fakeRule("A-002", model.SeverityHigh, rules.Fail("bad")),
		fakeRule("A-003", model.SeverityHigh, rules.Pass("ok")),
	}
	b := baseline.Baseline{
		Name:              "custom",
		Rules:             []string{"A-001", "A-002"},
		Exclusions:        map[string]string{"A-002": "accepted risk, ticket SEC-42"},
		SeverityOverrides: map[string]model.Severity{"A-001": model.SeverityCritical},
	}
	res := Run(&model.Snapshot{}, catalog, b)
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (A-003 not selected)", len(res.Findings))
	}
	byID := map[string]model.Finding{}
	for _, f := range res.Findings {
		byID[f.RuleID] = f
	}
	if f := byID["A-002"]; f.Status != model.StatusSkip || f.Message != "excluded by baseline: accepted risk, ticket SEC-42" {
		t.Errorf("excluded finding = %+v", f)
	}
	if f := byID["A-001"]; f.Severity != model.SeverityCritical || f.DefaultSeverity != model.SeverityLow {
		t.Errorf("override not applied: %+v", f)
	}
}

func TestRulesOutsideTheirPlatformsAreSkipped(t *testing.T) {
	called := false
	r := fakeRule("A-001", model.SeverityHigh, rules.Fail("bad"))
	r.Check = func(*model.Snapshot) rules.Result { called = true; return rules.Fail("bad") }
	f := Run(&model.Snapshot{Host: model.Host{OS: "windows"}}, []rules.Rule{r}, baseline.Default()).Findings[0]
	if called || f.Status != model.StatusSkip || f.Message != "not applicable on windows (rule targets linux)" {
		t.Fatalf("finding = %+v, check called = %v", f, called)
	}
}

func TestPanickingRuleBecomesError(t *testing.T) {
	catalog := []rules.Rule{
		{ID: "A-001", Severity: model.SeverityHigh, Check: func(s *model.Snapshot) rules.Result {
			panic("rule bug")
		}},
		fakeRule("A-002", model.SeverityLow, rules.Pass("ok")),
	}
	res := Run(&model.Snapshot{}, catalog, baseline.Default())
	if res.Findings[0].Status != model.StatusError || res.Summary.Pass != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestInvalidStatusBecomesError(t *testing.T) {
	catalog := []rules.Rule{fakeRule("A-001", model.SeverityLow, rules.Result{Status: "MAYBE"})}
	if f := Run(&model.Snapshot{}, catalog, baseline.Default()).Findings[0]; f.Status != model.StatusError {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestEvidenceIsCapped(t *testing.T) {
	ev := make([]string, MaxEvidence+25)
	for i := range ev {
		ev[i] = fmt.Sprint(i)
	}
	catalog := []rules.Rule{fakeRule("A-001", model.SeverityLow, rules.Fail("many", ev...))}
	f := Run(&model.Snapshot{}, catalog, baseline.Default()).Findings[0]
	if len(f.Evidence) != MaxEvidence+1 || f.Evidence[MaxEvidence] != "... 25 more evidence lines omitted" {
		t.Fatalf("evidence len = %d, last = %q", len(f.Evidence), f.Evidence[len(f.Evidence)-1])
	}
}
