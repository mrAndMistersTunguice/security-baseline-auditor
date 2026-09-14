# Architecture

This document describes how `sba` is structured, why, and how to extend it.

## Pipeline

```text
            ┌───────────── platform.Env ─────────────┐
            │ FS (bounded reads) · Runner · Elevated │
            └───────────────────┬────────────────────┘
                                │
   collector.Collect ──► model.Snapshot ──► engine.Run ──► []model.Finding ──► report
   (per-OS, gathers)     (normalized,       (baseline,     (status, evidence,  (text/JSON)
                          JSON-serializable) rules)         severity rationale)
```

1. **Collect.** `collector.Collect` dispatches on `env.GOOS` and fills a
   `model.Snapshot`. Collectors read files and system APIs only through
   `platform.Env`; they make no security judgement.
2. **Evaluate.** `engine.Run` selects rules according to the baseline, applies
   exclusions and severity overrides, runs each rule's `Check` against the
   snapshot and summarizes the results.
3. **Report.** `report` renders text or JSON; `cli` maps the result to an exit
   code.

## Package responsibilities

| Package | Responsibility | OS-specific code |
|---------|----------------|------------------|
| `cmd/sba` | Signal handling, process exit | no |
| `internal/cli` | Commands, flags, exit codes; dependencies injected through `cli.App` | no |
| `internal/platform` | `FS`, `Runner`, privilege detection; the only place that calls `os`, `os/exec` and `syscall` for collection | `osfs_{unix,windows,other}.go`, `exec_{unix,other}.go` |
| `internal/platform/platformtest` | In-memory `FS` and `Runner` fakes | no |
| `internal/collector` | OS dispatch; marks unimplemented sections `unsupported` | `collector_windows.go` |
| `internal/collector/sshd` | Portable OpenSSH configuration resolver | no |
| `internal/collector/accounts` | passwd, shadow, login.defs | no (reads via `FS`) |
| `internal/collector/firewall` | nftables JSON analysis, firewalld/ufw detection, Windows Firewall evaluation | `windows_windows.go` (registry, service manager) |
| `internal/collector/files`, `hostinfo` | File metadata, OS identification | `hostinfo/windows_windows.go` |
| `internal/model` | Data types shared by all layers | no |
| `internal/rules` | Rule type, catalog, checks | no |
| `internal/baseline` | YAML baseline parsing and validation | no |
| `internal/engine` | Rule execution and summary | no |
| `internal/report` | Rendering and output sanitization | no |

Dependencies point one way: `cli → collector/engine/report → rules/baseline → model`.
`rules` never imports `platform` or `collector` (tests do, to build realistic
snapshots).

### What is platform-specific and what is abstracted

Only the parts that must call OS APIs are platform-specific: file ownership
(`syscall.Stat_t`), non-blocking open, privilege detection, command execution,
registry and service-manager access. Everything that interprets data (sshd
resolution, passwd parsing, nftables analysis, Windows firewall profile
evaluation) is plain Go operating on bytes or small structs, so Linux logic is
tested on Windows and vice versa.

The Linux collectors themselves (`collectLinux`) have no build tag: they use
only `platform.FS` and `platform.Runner`, so the complete Linux collection path
is exercised on every CI platform with fixture filesystems.

Interfaces exist only where a second implementation is actually used: the real
OS and the test fake. There is no plugin system or dependency-injection
framework.

## Data model

`model.Snapshot` is platform-independent and JSON-serializable (`sba snapshot`
prints it). Each area is wrapped in a generic `model.Section[T]`:

```go
type Section[T any] struct {
    Status   CollectionStatus // collected | unsupported | not_found | permission_denied | failed
    Detail   string           // why it was not collected
    Warnings []string         // non-fatal parse problems
    Data     T
}
```

This is the central design decision. A zero-valued `Data` is ambiguous: an
empty user list could mean "no users" or "could not read /etc/passwd". Rules
must look at `Status` first, and the helper `rules.unavailable` maps statuses to
results consistently:

| Collection status | Rule result |
|-------------------|-------------|
| `collected` | rule evaluates `Data` → `PASS` / `FAIL` (or `ERROR` for invalid values) |
| `unsupported` | `SKIP` |
| `not_found` | `SKIP` (component absent, e.g. no SSH server) |
| `permission_denied` | `SKIP` with a hint to run elevated |
| `failed` | `ERROR` |

Sections can nest: `Accounts.Shadow` is its own section because `/etc/passwd`
is world-readable while `/etc/shadow` is not.

Additional normalization choices:

- **sshd:** directives are stored in processing order with file, line and the
  enclosing `Match` criteria; `SSHDConfig.Global` and `Conditional` implement
  "first value wins" and conditional overrides. Only documented keywords are
  stored.
- **Accounts:** password fields are reduced to `shadowed | empty | locked | hash`
  during parsing.
- **Firewall:** a list of *providers* (nftables ruleset, firewalld, ufw, Windows
  Defender Firewall), each with `State` (`enabled | disabled | unknown`),
  `RuntimeVerified` (live state vs configuration intent) and `Authoritative`
  (whether a `disabled` state is conclusive for the host). This lets one
  platform-independent rule reason correctly about very different sources:
  pass on runtime-verified filtering, fail only on authoritative absence,
  otherwise skip.

## Rule engine

```go
type Rule struct {
    ID, Title, Description string
    Category               model.Category
    Severity               model.Severity
    SeverityRationale      string
    Platforms              []string // GOOS values the rule is tested on
    Remediation            string
    References             []string // https only
    Check                  func(*model.Snapshot) Result
}
```

- Rules are plain values in a catalog (`rules.Builtin()`), not registered via
  `init()`, so the catalog is explicit and ordered.
- `rules.Validate` enforces ID format, uniqueness, complete metadata and https
  references; it runs in tests and at CLI startup.
- The engine skips rules whose `Platforms` do not include the host OS
  ("not applicable"), applies exclusions before running a check, converts
  panics and invalid statuses into `ERROR`, caps evidence at 50 lines and sorts
  findings by status, severity and ID for deterministic output.

## Baselines

`baseline.Parse` uses `go.yaml.in/yaml/v3` with `KnownFields(true)`, accepts
exactly one document and validates semantics (known rule IDs, no duplicates,
exclusions need a reason, excluded rules must be selected). All problems are
reported at once, sorted. The design choice is to fail closed: a typo must not
silently remove a check from an audit.

## Design review record

The following alternatives were considered and rejected for the MVP:

| Decision | Alternative | Reason |
|----------|-------------|--------|
| Static `sshd_config` resolver | Run `sshd -T` | Needs root and a trusted sshd binary, fails when the config is invalid, and evaluates `Match` only for a supplied connection. Kept on the roadmap as a cross-check. |
| Read `/etc/passwd` directly | `getent passwd` / NSS | NSS may enumerate thousands of directory accounts or block on network lookups; USER rules target local account files. Documented as a limitation. |
| `nft -j` JSON | Parse `nft list ruleset` text or `iptables-save` | JSON output has a documented schema; text output is not stable. Legacy iptables is reported as inconclusive rather than parsed. |
| Registry + service manager on Windows | `netsh advfirewall` / PowerShell | Command output is localized and slower; the API needs no process execution. |
| Standard library `flag` | Cobra/urfave | Four commands do not justify a dependency. |
| Sequential collection | Concurrent collectors | Collection takes milliseconds apart from one command; sequential code is simpler and deterministic. |
| No `--output` flag | Write report files | Writing files as root to user-chosen paths introduces symlink and permission issues; shell redirection already exists. |
| No `--root` for offline images | Audit a mounted filesystem | Needs careful confinement (absolute symlinks inside images point to the host). Possible future feature using `os.Root`. |

Dependencies: `go.yaml.in/yaml/v3` (the maintained YAML v3 module) and
`golang.org/x/sys` (Windows registry, tokens and service manager). Nothing else.

## Testing strategy

- **Parsers:** table-driven tests with realistic fixtures (Debian/Ubuntu- and
  RHEL-style `sshd_config` trees, passwd/shadow files, nftables JSON from
  firewalld, iptables-nft and hand-written rulesets) and malformed input.
- **Fuzzing:** native Go fuzz targets for the sshd, passwd/shadow, nftables and
  baseline parsers.
- **Rules:** each rule is tested against snapshots produced by the real parsers,
  including every collection status.
- **Platform layer:** real-filesystem tests for size limits, non-regular files,
  FIFOs, symlinks, the minimal child environment, untrusted binaries and
  timeouts (Unix-specific tests run in CI on Linux).
- **End-to-end:** `tests/integration` runs collectors → engine → report → CLI
  against complete fixture hosts, with a golden text report, an exit-code matrix,
  JSON schema decoding, unprivileged behaviour and panic recovery.
- **Documentation:** `docs/rules.md` is generated from the catalog and compared
  in tests; example baselines are validated against the catalog.
- **CI:** Linux and Windows, two Go versions, race detector, staticcheck for four
  target OSes, govulncheck, and real-binary smoke runs.

## Adding a rule

1. Make sure the data exists in the snapshot. If not, extend `model`, collect it
   in the appropriate collector with a correct `CollectionStatus` for every
   failure mode, and test the collector.
2. Add the rule to the relevant file in `internal/rules` with a unique ID,
   severity rationale, remediation and https references. Use `unavailable` for
   non-collected sections.
3. Add table-driven tests covering `PASS`, `FAIL` and each `SKIP`/`ERROR` path.
4. Update the end-to-end fixtures if the expected results change and regenerate
   golden files with `go test ./tests/integration -update`.

## Adding a platform

Implement a `collectX` function that fills every section, marking those it
cannot collect as `model.Unsupported`, and add the GOOS value to the
`Platforms` of rules that have been verified on it. A rule must not list a
platform where its data source has not been tested.
