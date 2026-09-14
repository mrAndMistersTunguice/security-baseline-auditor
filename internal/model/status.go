package model

// Status is the outcome of evaluating one rule.
//
//   - PASS:  the rule was evaluated against collected data and the system
//     meets the expectation.
//   - FAIL:  the rule was evaluated against collected data and the system
//     does not meet the expectation.
//   - SKIP:  the rule was deliberately not evaluated for a known, expected
//     reason: the platform is unsupported, the component is not present,
//     privileges are insufficient to read the data, or the baseline
//     excludes the rule. A SKIP never implies compliance.
//   - ERROR: evaluation was attempted but could not be completed because of
//     an unexpected condition (I/O failure, malformed data, an internal bug).
//     The outcome is unknown and needs attention.
type Status string

const (
	StatusPass  Status = "PASS"
	StatusFail  Status = "FAIL"
	StatusSkip  Status = "SKIP"
	StatusError Status = "ERROR"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusPass, StatusFail, StatusSkip, StatusError:
		return true
	}
	return false
}
