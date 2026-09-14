package baseline

import (
	"slices"
	"testing"
)

// FuzzParse checks that arbitrary YAML never panics and that every accepted
// baseline only references known rules.
func FuzzParse(f *testing.F) {
	f.Add("version: 1\n")
	f.Add("version: 1\nrules: [SSH-001]\nexclude:\n  - {rule: SSH-001, reason: x}\n")
	f.Add("version: 1\nseverity_overrides: {SSH-003: high}\n")
	f.Add("version: 1\n---\n&a [*a]\n")
	f.Fuzz(func(t *testing.T, input string) {
		b, err := Parse([]byte(input), "fuzz.yaml", known)
		if err != nil {
			return
		}
		for _, id := range b.Rules {
			if !slices.Contains(known, id) {
				t.Fatalf("accepted unknown rule %q", id)
			}
		}
		for id, reason := range b.Exclusions {
			if !slices.Contains(known, id) || reason == "" {
				t.Fatalf("accepted invalid exclusion %q: %q", id, reason)
			}
		}
		for id, sev := range b.SeverityOverrides {
			if !slices.Contains(known, id) || !sev.Valid() {
				t.Fatalf("accepted invalid override %q: %v", id, sev)
			}
		}
	})
}
