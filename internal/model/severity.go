// Package model defines the data types shared by collectors, rules, the
// engine and reporters. It has no dependencies on the operating system.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks the impact of a failed rule. The zero value is invalid so
// that a rule that forgets to set a severity is caught by validation.
type Severity int

const (
	SeverityInfo Severity = iota + 1
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

// AllSeverities lists severities from lowest to highest.
func AllSeverities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool {
	_, ok := severityNames[s]
	return ok
}

// ParseSeverity parses a severity name case-insensitively.
func ParseSeverity(name string) (Severity, error) {
	upper := strings.ToUpper(strings.TrimSpace(name))
	for sev, n := range severityNames {
		if n == upper {
			return sev, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (expected one of info, low, medium, high, critical)", name)
}

func (s Severity) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("cannot marshal invalid severity %d", int(s))
	}
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
