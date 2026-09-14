// Package report renders audit results as human-readable text or JSON.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/engine"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
)

// SchemaVersion is bumped on incompatible changes to the JSON report.
const SchemaVersion = "1"

// ScoreMethod is included in every report so the number is never shown
// without its definition.
const ScoreMethod = "severity-weighted percentage of evaluated rules (PASS or FAIL) that passed; " +
	"weights LOW=1 MEDIUM=2 HIGH=4 CRITICAL=8 INFO=0; SKIP and ERROR are excluded; " +
	"not a measure of overall security"

// Report is the complete audit output.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	Tool          Tool            `json:"tool"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Host          model.Host      `json:"host"`
	Baseline      BaselineInfo    `json:"baseline"`
	Summary       engine.Summary  `json:"summary"`
	ScoreMethod   string          `json:"score_method"`
	Notes         []string        `json:"notes,omitempty"`
	Findings      []model.Finding `json:"findings"`
}

// Tool identifies the auditor build.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// BaselineInfo identifies the baseline that was applied.
type BaselineInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// New assembles a report.
func New(snap *model.Snapshot, res engine.Result, b baseline.Baseline, version string) Report {
	r := Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "sba", Version: version},
		GeneratedAt:   snap.CollectedAt,
		Host:          snap.Host,
		Baseline:      BaselineInfo{Name: b.Name, Source: b.Source},
		Summary:       res.Summary,
		ScoreMethod:   ScoreMethod,
		Findings:      res.Findings,
	}
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	if !snap.Host.Elevated && res.Summary.Skip > 0 {
		r.Notes = append(r.Notes, "The audit did not run with elevated privileges; some checks may have been skipped. "+
			"Run as root (Linux) or from an elevated prompt (Windows) for full coverage.")
	}
	return r
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
