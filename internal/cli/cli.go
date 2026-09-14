// Package cli implements the sba command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/baseline"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/collector"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/engine"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/model"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/platform"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/report"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/rules"
	"github.com/mrAndMistersTunguice/security-baseline-auditor/internal/version"
)

// Exit codes.
const (
	// ExitOK: the command completed; for audit, no FAIL at or above the
	// --fail-on threshold and no ERROR findings.
	ExitOK = 0
	// ExitFindings: the audit completed with FAIL findings at or above the
	// threshold, or with ERROR findings.
	ExitFindings = 1
	// ExitUsage: invalid arguments or an invalid baseline file.
	ExitUsage = 2
	// ExitRuntime: the command could not complete (for example, writing the
	// report failed or an internal error occurred).
	ExitRuntime = 3
)

// App holds the dependencies of the CLI so tests can substitute them.
type App struct {
	Stdout, Stderr io.Writer
	// Env is the platform used for collection and for reading --config.
	Env platform.Env
	// Catalog is the rule catalog.
	Catalog []rules.Rule
	// Collect produces a snapshot; tests can replace it with a fixture.
	Collect func(context.Context, platform.Env) *model.Snapshot
}

// New returns an App wired to the real system.
func New(stdout, stderr io.Writer) *App {
	return &App{
		Stdout:  stdout,
		Stderr:  stderr,
		Env:     platform.Host(),
		Catalog: rules.Builtin(),
		Collect: collector.Collect,
	}
}

const usage = `sba - security baseline auditor

Usage:
  sba audit [--format text|json] [--config FILE] [--fail-on SEVERITY]
  sba snapshot
  sba rules list [--format text|json]
  sba version

Commands:
  audit        Collect system data, evaluate rules and print a report
  snapshot     Print the collected, normalized system data as JSON
  rules list   List the built-in rules
  version      Print the version

Global flags:
  -h, --help     Show help
  --version      Print the version

Exit codes:
  0  completed; no failures at or above --fail-on and no errors
  1  audit completed with failures at or above --fail-on, or with errors
  2  usage or configuration error
  3  runtime error
`

// Run executes the CLI and returns the process exit code. Internal panics
// are reported as a one-line error instead of a stack trace.
func (a *App) Run(ctx context.Context, args []string) (code int) {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintf(a.Stderr, "sba: internal error: %v (please report this as a bug)\n", p)
			code = ExitRuntime
		}
	}()

	if err := rules.Validate(a.Catalog); err != nil {
		fmt.Fprintf(a.Stderr, "sba: internal error: invalid rule catalog: %v\n", err)
		return ExitRuntime
	}

	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "-help", "help":
		fmt.Fprint(a.Stdout, usage)
		return ExitOK
	case "--version", "-version", "version":
		if args[0] == "version" && len(args) > 1 {
			return a.usageError("version takes no arguments")
		}
		fmt.Fprintf(a.Stdout, "sba %s\n", version.String())
		return ExitOK
	case "audit":
		return a.audit(ctx, args[1:])
	case "snapshot":
		return a.snapshot(ctx, args[1:])
	case "rules":
		if len(args) < 2 || args[1] != "list" {
			return a.usageError("expected 'sba rules list'")
		}
		return a.rulesList(args[2:])
	default:
		return a.usageError(fmt.Sprintf("unknown command %q", args[0]))
	}
}

func (a *App) usageError(msg string) int {
	fmt.Fprintf(a.Stderr, "sba: %s\nRun 'sba --help' for usage.\n", msg)
	return ExitUsage
}

// newFlagSet creates a flag set that reports errors through usageError
// instead of printing flag package defaults to stdout.
func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func (a *App) parseFlags(fs *flag.FlagSet, args []string, help string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.Stdout, help)
			return ExitOK, false
		}
		return a.usageError(err.Error()), false
	}
	if fs.NArg() > 0 {
		return a.usageError(fmt.Sprintf("unexpected argument %q", fs.Arg(0))), false
	}
	return 0, true
}

func validFormat(f string) bool { return f == "text" || f == "json" }

const auditHelp = `Usage: sba audit [flags]

Flags:
  --format text|json   Output format (default text)
  --config FILE        Baseline YAML file (default: all built-in rules)
  --fail-on SEVERITY   Lowest FAIL severity that yields exit code 1:
                       info, low, medium, high, critical, or none to always
                       exit 0 when the audit completes (default low)
`

func (a *App) audit(ctx context.Context, args []string) int {
	fs := a.newFlagSet("audit")
	format := fs.String("format", "text", "")
	configPath := fs.String("config", "", "")
	failOn := fs.String("fail-on", "low", "")
	if code, ok := a.parseFlags(fs, args, auditHelp); !ok {
		return code
	}
	if !validFormat(*format) {
		return a.usageError(fmt.Sprintf("invalid --format %q (expected text or json)", *format))
	}
	threshold, err := parseFailOn(*failOn)
	if err != nil {
		return a.usageError(err.Error())
	}

	b := baseline.Default()
	if *configPath != "" {
		b, err = baseline.Load(a.Env.FS, *configPath, ruleIDs(a.Catalog), a.Env.Elevated)
		if err != nil {
			fmt.Fprintf(a.Stderr, "sba: %v\n", err)
			return ExitUsage
		}
	}

	snap := a.Collect(ctx, a.Env)
	if err := ctx.Err(); err != nil {
		fmt.Fprintf(a.Stderr, "sba: audit interrupted: %v\n", err)
		return ExitRuntime
	}
	res := engine.Run(snap, a.Catalog, b)
	rep := report.New(snap, res, b, version.String())

	if *format == "json" {
		err = report.WriteJSON(a.Stdout, rep)
	} else {
		err = report.WriteText(a.Stdout, rep)
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "sba: writing report: %v\n", err)
		return ExitRuntime
	}
	return exitCode(res, threshold)
}

// parseFailOn returns the threshold severity, or 0 for "none".
func parseFailOn(v string) (model.Severity, error) {
	if strings.EqualFold(v, "none") {
		return 0, nil
	}
	sev, err := model.ParseSeverity(v)
	if err != nil {
		return 0, fmt.Errorf("invalid --fail-on %q (expected info, low, medium, high, critical or none)", v)
	}
	return sev, nil
}

func exitCode(res engine.Result, threshold model.Severity) int {
	if threshold == 0 {
		return ExitOK
	}
	for _, f := range res.Findings {
		if f.Status == model.StatusError || (f.Status == model.StatusFail && f.Severity >= threshold) {
			return ExitFindings
		}
	}
	return ExitOK
}

const snapshotHelp = `Usage: sba snapshot

Prints the normalized system snapshot as JSON. The snapshot contains host
names, account names and configuration details; treat it as sensitive.
Password hashes are never included.
`

func (a *App) snapshot(ctx context.Context, args []string) int {
	fs := a.newFlagSet("snapshot")
	if code, ok := a.parseFlags(fs, args, snapshotHelp); !ok {
		return code
	}
	snap := a.Collect(ctx, a.Env)
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		fmt.Fprintf(a.Stderr, "sba: writing snapshot: %v\n", err)
		return ExitRuntime
	}
	return ExitOK
}

const rulesHelp = `Usage: sba rules list [--format text|json]
`

type ruleInfo struct {
	ID                string         `json:"id"`
	Title             string         `json:"title"`
	Description       string         `json:"description"`
	Category          model.Category `json:"category"`
	Severity          model.Severity `json:"severity"`
	SeverityRationale string         `json:"severity_rationale"`
	Platforms         []string       `json:"platforms"`
	Remediation       string         `json:"remediation"`
	References        []string       `json:"references"`
}

func (a *App) rulesList(args []string) int {
	fs := a.newFlagSet("rules list")
	format := fs.String("format", "text", "")
	if code, ok := a.parseFlags(fs, args, rulesHelp); !ok {
		return code
	}
	if !validFormat(*format) {
		return a.usageError(fmt.Sprintf("invalid --format %q (expected text or json)", *format))
	}

	infos := make([]ruleInfo, 0, len(a.Catalog))
	for _, r := range a.Catalog {
		infos = append(infos, ruleInfo{
			ID: r.ID, Title: r.Title, Description: r.Description, Category: r.Category,
			Severity: r.Severity, SeverityRationale: r.SeverityRationale, Platforms: r.Platforms,
			Remediation: r.Remediation, References: r.References,
		})
	}

	var err error
	if *format == "json" {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(infos)
	} else {
		tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tPLATFORMS\tTITLE")
		for _, r := range infos {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Category, strings.Join(r.Platforms, ","), r.Title)
		}
		err = tw.Flush()
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "sba: writing rules: %v\n", err)
		return ExitRuntime
	}
	return ExitOK
}

func ruleIDs(catalog []rules.Rule) []string {
	ids := make([]string, len(catalog))
	for i, r := range catalog {
		ids[i] = r.ID
	}
	return ids
}
