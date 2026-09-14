// Package baseline loads and validates baseline configuration files that
// select rules, exclude rules with a documented reason and override
// severities.
package baseline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
)

// MaxFileSize bounds baseline files. Real baselines are a few kilobytes.
const MaxFileSize = 1 << 20

// SupportedVersion is the only accepted value of the version field.
const SupportedVersion = 1

// Baseline is a validated baseline.
type Baseline struct {
	Name string
	// Source is the file the baseline came from, or "built-in".
	Source string
	// Rules selects rules by ID. Empty means all built-in rules.
	Rules []string
	// Exclusions maps rule IDs to the documented reason for excluding them.
	Exclusions map[string]string
	// SeverityOverrides maps rule IDs to a replacement severity.
	SeverityOverrides map[string]model.Severity
}

// Default is the baseline used without --config: every built-in rule.
func Default() Baseline {
	return Baseline{Name: "default (all built-in rules)", Source: "built-in"}
}

// file is the on-disk schema.
type file struct {
	Version           int               `yaml:"version"`
	Name              string            `yaml:"name"`
	Rules             []string          `yaml:"rules"`
	Exclude           []exclusion       `yaml:"exclude"`
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
}

type exclusion struct {
	Rule   string `yaml:"rule"`
	Reason string `yaml:"reason"`
}

// Load reads and parses a baseline file.
func Load(fsys platform.FS, path string, knownRules []string) (Baseline, error) {
	data, err := fsys.ReadFile(path, MaxFileSize)
	if err != nil {
		if errors.Is(err, platform.ErrTooLarge) {
			return Baseline{}, fmt.Errorf("baseline %s is larger than %d bytes", path, MaxFileSize)
		}
		return Baseline{}, fmt.Errorf("cannot read baseline: %w", err)
	}
	return Parse(data, path, knownRules)
}

// Parse decodes baseline YAML strictly: unknown fields, unknown rule IDs,
// duplicates and exclusions without a reason are errors, because a typo
// that silently disables a check would give a false sense of compliance.
func Parse(data []byte, source string, knownRules []string) (Baseline, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return Baseline{}, fmt.Errorf("baseline %s is empty", source)
		}
		return Baseline{}, fmt.Errorf("baseline %s: %w", source, err)
	}
	// Decode into a yaml.Node, which keeps aliases as references instead of
	// expanding them, so a hostile trailing document cannot blow up memory.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Baseline{}, fmt.Errorf("baseline %s: must contain exactly one YAML document", source)
	}

	if f.Version != SupportedVersion {
		return Baseline{}, fmt.Errorf("baseline %s: unsupported version %d (expected %d)", source, f.Version, SupportedVersion)
	}

	var errs []error
	known := func(id string) bool { return slices.Contains(knownRules, id) }

	b := Baseline{
		Name:              strings.TrimSpace(f.Name),
		Source:            source,
		Exclusions:        map[string]string{},
		SeverityOverrides: map[string]model.Severity{},
	}
	if b.Name == "" {
		b.Name = source
	}

	seen := map[string]bool{}
	for _, id := range f.Rules {
		switch {
		case !known(id):
			errs = append(errs, fmt.Errorf("rules: unknown rule ID %q", id))
		case seen[id]:
			errs = append(errs, fmt.Errorf("rules: duplicate rule ID %q", id))
		}
		seen[id] = true
		b.Rules = append(b.Rules, id)
	}
	if f.Rules != nil && len(f.Rules) == 0 {
		errs = append(errs, errors.New("rules: list is empty; omit the field to select all rules"))
	}

	selected := func(id string) bool { return len(f.Rules) == 0 || seen[id] }

	for _, ex := range f.Exclude {
		switch {
		case !known(ex.Rule):
			errs = append(errs, fmt.Errorf("exclude: unknown rule ID %q", ex.Rule))
		case strings.TrimSpace(ex.Reason) == "":
			errs = append(errs, fmt.Errorf("exclude: rule %s needs a reason", ex.Rule))
		case !selected(ex.Rule):
			errs = append(errs, fmt.Errorf("exclude: rule %s is not selected in rules", ex.Rule))
		case b.Exclusions[ex.Rule] != "":
			errs = append(errs, fmt.Errorf("exclude: rule %s listed twice", ex.Rule))
		default:
			b.Exclusions[ex.Rule] = strings.TrimSpace(ex.Reason)
		}
	}

	for id, name := range f.SeverityOverrides {
		sev, err := model.ParseSeverity(name)
		switch {
		case !known(id):
			errs = append(errs, fmt.Errorf("severity_overrides: unknown rule ID %q", id))
		case err != nil:
			errs = append(errs, fmt.Errorf("severity_overrides: %s: %w", id, err))
		default:
			b.SeverityOverrides[id] = sev
		}
	}

	if err := errors.Join(errs...); err != nil {
		return Baseline{}, fmt.Errorf("baseline %s is invalid:\n%w", source, sortedErrors(errs))
	}
	return b, nil
}

// sortedErrors gives deterministic error output (map iteration is random).
func sortedErrors(errs []error) error {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = "  - " + e.Error()
	}
	slices.Sort(msgs)
	return errors.New(strings.Join(msgs, "\n"))
}
