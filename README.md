# security-baseline-auditor

[![CI](https://github.com/mrAndMistersTunguice/security-baseline-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/mrAndMistersTunguice/security-baseline-auditor/actions/workflows/ci.yml)

Cross-platform security baseline auditing tool written in Go.

`sba` collects security-relevant settings from the local Linux or Windows
system, normalizes them into a platform-independent snapshot, evaluates a set
of rules against that snapshot and prints a report that explains every result
with evidence.

```text
Collector → Normalized snapshot → Rule engine → Findings → Report
```

> **Project status: early MVP (v0.x).** The tool is useful for learning,
> experiments and as a second opinion on a host, but it is not a replacement for
> a mature compliance scanner. It does not claim conformance with CIS Benchmarks,
> DISA STIGs or any other standard. See [Limitations](#limitations).

## Contents

- [Why](#why)
- [What it does today](#what-it-does-today)
- [What it does not do](#what-it-does-not-do)
- [Installation](#installation)
- [Usage](#usage)
- [Example output](#example-output)
- [Results, severity and score](#results-severity-and-score)
- [Supported platforms](#supported-platforms)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Development](#development)
- [License](#license)

## Why

Hardening guides are long, and ad-hoc audit scripts tend to have the same
weaknesses: they grep a single configuration file and miss `Include` drop-ins,
they report "OK" when they could not actually read the data, they mix data
collection with judgement so they cannot be tested, and their output cannot be
consumed by automation.

This project is an attempt to do the small subset it covers carefully:

- **Collection is separated from evaluation.** Collectors only gather data;
  rules are pure functions of the snapshot and are tested on any OS.
- **Unknown is never reported as compliant.** Every snapshot section carries a
  collection status. Missing privileges, missing components and unsupported
  platforms produce `SKIP`, unexpected failures produce `ERROR`, never `PASS`.
- **Every result has evidence**, for example the exact `sshd_config` file and
  line that produced a value, and an explanation of its severity.
- **Machine-readable output** (JSON) and meaningful exit codes for CI.

## What it does today

- **22 built-in rules** ([full reference](docs/rules.md)):
  - **SSH (SSH-001..009)**: root login, password and keyboard-interactive
    authentication, empty passwords, `PermitUserEnvironment`, `MaxAuthTries`,
    X11 forwarding, weak ciphers/MACs/key exchange algorithms.
  - **Accounts (USER-001..005)**: additional UID 0 accounts, empty passwords,
    hashes in `/etc/passwd`, duplicate UIDs, system accounts with login shells.
  - **Firewall (FW-001)**: inbound filtering on Linux (nftables ruleset,
    firewalld) and Windows (Windows Defender Firewall profiles and service).
  - **File permissions (FILE-001..007)**: `/etc/shadow`, `/etc/gshadow`,
    `/etc/passwd`, `/etc/group`, `/etc/sudoers`, `/etc/ssh/sshd_config`, sticky
    bit on `/tmp` and `/var/tmp`.
- **OpenSSH configuration resolver** that follows OpenSSH semantics: first
  value wins, `Include` with globs in lexical order (Debian/Ubuntu and
  RHEL/Fedora drop-in layouts), relative includes, `Match` blocks (settings
  inside `Match` are evaluated as conditional overrides), quoting and `=`
  syntax, deprecated keyword aliases, include depth limit.
- **nftables ruleset analysis** from `nft -j list ruleset` (run only as root):
  follows `jump`/`goto` and verdict maps from input-hook base chains and detects
  whether a `drop`/`reject` is reachable. Loaded legacy iptables tables make the
  result inconclusive instead of wrong.
- **Baselines in YAML**: select rules, exclude rules with a mandatory reason
  (excluded rules stay visible as `SKIP`), override severities. Parsing is
  strict: typos and unknown rule IDs are errors.
- **Reports**: human-readable text and JSON (with schema version), a documented
  severity-weighted score with coverage, and `sba snapshot` to inspect the raw
  normalized data.
- **CLI**: `audit`, `snapshot`, `rules list`, `version`, `--help`, exit codes
  suitable for CI (`--fail-on` threshold).

## What it does not do

- It does **not** remediate anything. It never modifies the system.
- It does **not** evaluate `Match` criteria (it cannot know future connections);
  any risky value inside a `Match` block fails the rule, with the block shown.
- It does **not** ask `sshd` for its effective configuration (`sshd -T`), and
  does not know the installed OpenSSH version; defaults are those documented for
  current OpenSSH releases.
- It does **not** inspect accounts from LDAP/SSSD/NIS, PAM configuration,
  sudoers content, SELinux/AppArmor, kernel parameters, services, patches or
  listening ports.
- On **Windows** it does **not** collect local accounts or file ACLs; those
  rules report "not applicable". Third-party firewalls and MDM-delivered
  firewall policy are not detected.
- Firewall analysis on Linux detects that inbound filtering **exists**, not that
  the policy is default-deny or that specific ports are protected.
- **macOS and BSD** builds compile but no rule is evaluated there.

## Installation

Requires Go 1.26 or newer.

```bash
go install github.com/mrAndMistersTunguice/security-baseline-auditor/cmd/sba@latest
```

From source:

```bash
git clone https://github.com/mrAndMistersTunguice/security-baseline-auditor.git
cd security-baseline-auditor
go build -trimpath -o sba ./cmd/sba
```

No release binaries are published yet.

## Usage

```text
sba audit [--format text|json] [--config FILE] [--fail-on SEVERITY]
sba snapshot
sba rules list [--format text|json]
sba version
```

Run as an unprivileged user first; run with `sudo` (Linux) or from an elevated
prompt (Windows) for full coverage. Checks that need privileges are reported as
`SKIP` with a reason, not guessed.

```bash
# Text report
sudo sba audit

# JSON for automation; do not fail the pipeline on findings
sudo sba audit --format json --fail-on none > report.json

# Fail only on HIGH and CRITICAL findings (or any ERROR)
sudo sba audit --fail-on high

# Apply a custom baseline
sudo sba audit --config configs/example-baseline.yaml

# List rules, inspect collected data
sba rules list
sudo sba snapshot
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed; no `FAIL` at or above `--fail-on` (default `low`) and no `ERROR` |
| 1 | Audit completed with `FAIL` findings at or above the threshold, or with `ERROR` findings |
| 2 | Usage error or invalid baseline file |
| 3 | Runtime error (for example, the report could not be written) |

`--fail-on none` always exits 0 when the audit completes.

### Baselines

```yaml
version: 1
name: "Linux web servers"
rules:            # omit to evaluate every built-in rule
  - SSH-001
  - SSH-003
  - FW-001
exclude:
  - rule: FW-001
    reason: "Filtering is enforced by the upstream appliance (ticket NET-42)"
severity_overrides:
  SSH-003: high
```

See [configs/](configs/) for commented examples. When `sba` runs with elevated
privileges it refuses a baseline file that is writable by group or others,
because such a file would let a local user hide findings.

## Example output

The excerpt below is the report for the deliberately insecure test fixture in
[`tests/testdata/insecure`](tests/testdata/insecure) (the full text is kept as a
golden file in [`tests/testdata/insecure-report.golden.txt`](tests/testdata/insecure-report.golden.txt)).
It is not output from a real server.

```text
Security Baseline Audit
=======================

Host:        fixture-host (Ubuntu 24.04.1 LTS, linux/amd64)
Privileges:  elevated
Baseline:    default (all built-in rules) (built-in)
Tool:        sba test
Time:        2026-01-02 03:04:05 UTC

Summary
-------
Rules:       22 selected: 4 PASS, 17 FAIL, 1 SKIP, 0 ERROR
Failed:      CRITICAL 2 | HIGH 5 | MEDIUM 6 | LOW 4 | INFO 0
Score:       21/100 over 21 of 22 selected rules
             (severity-weighted percentage of evaluated rules (PASS or FAIL) that passed; ...)

Failed checks (17)
------------------

[CRITICAL] USER-001  Only root may have UID 0
  Result:      1 account(s) other than root have UID 0
  Evidence:
    - toor has UID 0 (/etc/passwd line 5)
  Severity:    CRITICAL. An extra UID 0 account is equivalent to a second root account and typically indicates compromise or a severe misconfiguration.
  Remediation: Remove the account or assign it a unique non-zero UID after investigating why it exists.
  Reference:   https://man7.org/linux/man-pages/man5/passwd.5.html

[HIGH] SSH-001  SSH root login with a password must not be allowed
  Result:      root login with password authentication is permitted
  Evidence:
    - PermitRootLogin yes (/etc/ssh/sshd_config:2)
  ...

[MEDIUM] SSH-003  SSH password authentication should be disabled
  Result:      password authentication is enabled
  Evidence:
    - PasswordAuthentication yes (/etc/ssh/sshd_config.d/50-cloud-init.conf:1)
  ...

Skipped checks (1)
------------------
[MEDIUM] FILE-002  /etc/gshadow must not be accessible to other users
    /etc/gshadow does not exist
```

## Results, severity and score

| Status | Meaning |
|--------|---------|
| `PASS` | The rule was evaluated against collected data and the system meets the expectation. |
| `FAIL` | The rule was evaluated against collected data and the system does not meet the expectation. |
| `SKIP` | The rule was deliberately not evaluated for a known, expected reason: rule not applicable on this OS, component not installed, insufficient privileges, or excluded by the baseline. A `SKIP` never implies compliance. |
| `ERROR` | Evaluation was attempted but failed unexpectedly (I/O error, configuration that `sshd` itself would reject, internal bug). The outcome is unknown and needs attention; it makes `sba audit` exit with code 1 unless `--fail-on none` is used. |

**Severity** (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) is assigned per rule
and every rule carries a written rationale that is printed with the finding.
Roughly: `CRITICAL` means direct, reliable privilege escalation or an indicator
of compromise; `HIGH` means remote access or credential exposure without further
preconditions; `MEDIUM` requires an additional condition (a weak password, an
authenticated user); `LOW` is defence in depth. Baselines can override
severities; reports then show both values.

**Score** is a severity-weighted percentage of evaluated rules that passed
(weights LOW=1, MEDIUM=2, HIGH=4, CRITICAL=8), always shown together with how
many rules were evaluated. It is a convenience for tracking one host over time,
not a measure of security. See [docs/scoring.md](docs/scoring.md).

## Supported platforms

| Platform | Status | What is evaluated | How it is tested |
|----------|--------|-------------------|------------------|
| Linux | Primary | All 22 rules | Unit and end-to-end tests with Debian/Ubuntu- and RHEL-style fixtures on every CI run; real-binary smoke test (unprivileged and root) on the GitHub-hosted Ubuntu runner. Not yet validated on real RHEL, Fedora, SUSE or Alpine hosts. |
| Windows | Partial | FW-001; SSH-001..009 when an OpenSSH Server configuration exists in `%ProgramData%\ssh` | Unit tests, CI on `windows-latest`, manual run on Windows 11 (firewall result cross-checked with `Get-NetFirewallProfile`). The SSH path uses the same parser as Linux but has not been validated against a real Windows OpenSSH Server installation. Account and file-permission rules are reported as not applicable. |
| macOS, FreeBSD | Not supported | Nothing (all rules `SKIP`) | Cross-compilation only. |

## Architecture

```text
cmd/sba                  entry point (signal handling, exit code)
internal/cli             commands, flags, exit codes
internal/platform        OS access behind interfaces: bounded file reads,
                         hardened command runner, privilege detection
internal/collector       builds model.Snapshot per OS
  ├── sshd               OpenSSH configuration resolver (portable)
  ├── accounts           passwd / shadow / login.defs parsers
  ├── firewall           nftables JSON analysis, firewalld, ufw, Windows Firewall
  ├── files              ownership and mode of security-relevant paths
  └── hostinfo           os-release, kernel, Windows version
internal/model           snapshot, severities, statuses, findings (no OS code)
internal/rules           rule catalog; pure functions of the snapshot
internal/baseline        strict YAML baseline loading and validation
internal/engine          selection, exclusions, overrides, panic isolation, summary
internal/report          text and JSON rendering, terminal-safe output
configs/                 example baselines (validated by tests)
tests/                   end-to-end tests and host fixtures
docs/                    rule reference and scoring method
```

Design decisions, the data model and the extension points are described in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Security model

`sba` often runs as root, and it parses files that an attacker may control, so
it is written defensively. Summary (details in [SECURITY.md](SECURITY.md)):

- It never modifies the system, writes no files and creates no temporary files.
- It never invokes a shell. The only external program is `nft`, executed on
  Linux as root from a fixed absolute path, after verifying that the binary and
  every parent directory are owned by root and not group/world-writable, with a
  fixed minimal environment, a timeout and bounded output. Windows collectors
  use the registry and service manager APIs and execute nothing.
- All file reads are size-limited, refuse non-regular files and do not block on
  FIFOs. Include depth, file count, directive count and evidence size are bounded.
- Password hashes are classified and discarded during parsing; warnings about
  malformed account lines contain line numbers only; unknown `sshd_config`
  keywords are not stored.
- Text reports escape control characters, invalid UTF-8 and bidirectional
  Unicode formatting characters from system data (terminal injection).
- Reports and snapshots contain host names, account names and configuration
  details. Treat them as sensitive.

## Limitations

- Static analysis of `sshd_config` can differ from the running daemon (changed
  but not reloaded configuration, compile-time defaults, distribution patches,
  command-line options).
- Accounts are read from local files only; directory-service accounts are
  invisible.
- Without root, `/etc/shadow`, RHEL-style `sshd_config` (mode 0600) and the
  nftables ruleset cannot be read; affected rules are skipped.
- `FW-001` on Linux treats any reachable `drop`/`reject` in an input chain as
  filtering. Rules managed exclusively through legacy iptables make the result
  inconclusive. On Windows, a disabled Windows Defender Firewall with an active
  third-party firewall is reported as `FAIL`; exclude the rule with a reason in
  that case.
- The rule set is small and opinionated (for example, SSH password
  authentication is expected to be disabled). Use baselines to adapt it.
- The score is not comparable between hosts with different coverage.
- The project has not had an independent security review.

## Roadmap

Planned, not implemented:

- Optional cross-check of the effective SSH configuration with `sshd -T`.
- Windows local accounts (built-in Administrator/Guest state) and ACL-based file
  checks.
- Linux: sudoers content, PAM `nullok`, kernel parameters (`sysctl`), listening
  services.
- Default-deny policy analysis for nftables and legacy iptables support.
- Rule parameters in baselines (for example a custom `MaxAuthTries` limit).
- Signed release binaries and SBOM.

## Development

```bash
go test ./...
go test -race ./...          # requires cgo (Linux/macOS)
go vet ./...
gofmt -l .
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

# Fuzz a parser
go test ./internal/collector/sshd -run '^$' -fuzz FuzzLoad -fuzztime 60s

# Regenerate golden files (report fixture, docs/rules.md) after intentional changes
go test ./tests/integration -update
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule.

## License

[MIT](LICENSE)
