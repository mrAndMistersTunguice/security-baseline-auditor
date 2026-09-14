package model

// Category groups rules by the area of the system they inspect.
type Category string

const (
	CategorySSH      Category = "ssh"
	CategoryAccounts Category = "accounts"
	CategoryFirewall Category = "firewall"
	CategoryFiles    Category = "file-permissions"
)

// Finding is the result of evaluating one rule against a snapshot.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	// DefaultSeverity differs from Severity when the baseline overrides it.
	DefaultSeverity   Severity `json:"default_severity"`
	SeverityRationale string   `json:"severity_rationale"`
	Status            Status   `json:"status"`
	// Message is a one-line explanation of the status.
	Message     string   `json:"message"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}
