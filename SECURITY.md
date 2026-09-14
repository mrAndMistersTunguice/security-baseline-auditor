# Security

## Reporting a vulnerability

Please report vulnerabilities in `sba` privately through GitHub's
[private vulnerability reporting](https://github.com/mrAndMistersTunguice/security-baseline-auditor/security/advisories/new)
rather than in a public issue. Include the version (`sba --version`), the
platform, and steps or input files to reproduce the problem.

This is a personal project maintained on a best-effort basis; there is no
guaranteed response time. Only the latest commit on `main` receives fixes.

## Threat model

`sba` is typically run by an administrator, often as root or from an elevated
prompt, on a host that may already be misconfigured or compromised. It
therefore treats everything it reads from the system as untrusted:

- configuration files and anything they include (`sshd_config` and drop-ins),
- account databases,
- the output of `nft`,
- process information from `/proc`,
- the baseline file passed with `--config`.

Goals:

1. Reading hostile data must not lead to code execution, unbounded resource use,
   a crash, or corruption of the terminal.
2. The tool must not disclose secrets (password hashes, unrelated file content)
   in reports, snapshots or error messages.
3. A local unprivileged user must not be able to influence what a root-run audit
   executes or which checks it performs.
4. Missing data must never be reported as compliant.

Non-goals:

- Detecting an attacker who already has root. A root-level attacker can tamper
  with every data source and with the binary itself.
- Protecting reports after they are written to stdout.
- Safe delegation through `sudo` to untrusted users (see below).

## Controls

### Process execution

- No shell is ever invoked (`sh -c`, `cmd /c`, PowerShell).
- The only external command is `nft -j list ruleset`, executed on Linux only
  when running as root, from fixed absolute paths (`PATH` is not consulted).
- Before execution, the binary path is fully resolved and the binary and every
  parent directory must be owned by root and not writable by group or others;
  the resolved path is what gets executed.
- The child receives a fixed environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
  `LC_ALL=C`), so variables such as `LD_PRELOAD` are not inherited.
- A 15-second timeout, `WaitDelay`, 16 MiB stdout and 64 KiB stderr limits apply.
- Non-Unix builds refuse to execute any program.

### File access

- Reads go through `platform.FS.ReadFile`, which opens the file, checks the
  type of the opened descriptor (not the path, avoiding a stat/open race),
  rejects non-regular files, opens with `O_NONBLOCK` on Unix so FIFOs cannot
  hang the audit, and enforces a size limit without trusting the reported size.
- Limits: 1 MiB per sshd configuration file, 256 included files, include depth
  16, 100 000 directives, 32 MiB account databases, 1 MiB baseline files,
  200 000 `/proc` entries.
- No files are written and no temporary files are created.

### Parsing

- YAML baselines are decoded strictly into typed structs; unknown fields,
  multiple documents and unknown rule IDs are rejected. Alias expansion is
  bounded by the typed schema and by go-yaml's own alias limits.
- JSON from `nft` is decoded with `encoding/json`; recursion into expressions
  and chain jumps is depth-limited and cycle-safe.
- All parsers have fuzz targets.

### Information disclosure

- Password hashes from `/etc/passwd` and `/etc/shadow` are reduced to a state
  (`empty`, `locked`, `hash`, `shadowed`) during parsing and never stored.
- Warnings about malformed account lines include only line numbers.
- sshd syntax errors quote a keyword only if it looks like a real sshd keyword,
  and directives with unknown keywords are dropped, so a malicious `Include`
  of an unrelated file cannot copy its content into output.
- Reports and snapshots do contain host names, account names, file paths and
  configuration values. Handle them as sensitive operational data.

### Output

- The text report escapes C0/C1 control characters, DEL, invalid UTF-8 and
  Unicode bidirectional formatting characters, preventing terminal escape
  injection from crafted configuration content.
- JSON output relies on `encoding/json`, which escapes control characters.

### Integrity of the audit

- When running elevated, a baseline file writable by group or others is
  refused, because it could be used to exclude checks.
- Each rule runs with panic isolation; a failing rule becomes `ERROR`, and
  `ERROR` findings make `sba audit` exit non-zero (unless `--fail-on none`).

## Known limitations and residual risks

- **`sudo` delegation is not supported as a security boundary.** Granting an
  untrusted user `sudo sba` lets that user make `sba` read arbitrary files as
  root via `--config`; parse errors may reveal fragments such as the first
  characters of a value or top-level keys. Only trusted administrators should
  run `sba` with elevated privileges.
- The group/world-writable check on baselines does not inspect parent
  directories, and ownership is not checked on Windows.
- `/proc`-based firewalld detection requires a root-owned process named
  `firewalld`; it proves a process is running, not that its rules are loaded.
- Directory globbing for `Include` patterns is performed by `filepath.Glob`
  before the file-count limit applies; a pathological pattern in a root-owned
  configuration file can make collection slow.
- The project has not undergone an independent security audit.
