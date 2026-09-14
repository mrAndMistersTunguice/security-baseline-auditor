# Contributing

Thanks for your interest in improving `sba`. Bug reports, false-positive
reports with the relevant (sanitized) configuration, and new rules are welcome.

## Ground rules

- **No fake results.** If data cannot be collected reliably, mark the section
  with the appropriate `model.CollectionStatus` so rules return `SKIP` or
  `ERROR`. Never return `PASS` for data that was not inspected.
- **Collectors collect, rules judge.** Collectors must not contain security
  decisions; rules must not access the operating system.
- **No unverified claims.** Do not describe a rule as CIS/STIG/NIST compliant
  unless it has been checked against that document, and cite the document.
- **Keep dependencies minimal.** Prefer the standard library. A new dependency
  needs a justification in the pull request.
- **Security-sensitive code** (`internal/platform`, parsers) needs tests for
  malformed and hostile input. Never invoke a shell.

## Development setup

Requires Go 1.26 or newer.

```bash
git clone https://github.com/mrAndMistersTunguice/security-baseline-auditor.git
cd security-baseline-auditor
go build ./...
go test ./...
```

Before opening a pull request, run:

```bash
gofmt -l .                  # must print nothing
go vet ./...
go test ./...
go test -race ./...         # Linux/macOS
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
```

If you changed rule metadata or report formatting, regenerate and review the
golden files:

```bash
go test ./tests/integration -update
git diff docs/rules.md tests/testdata
```

For parser changes, run the relevant fuzz target for a while, for example:

```bash
go test ./internal/collector/sshd -run '^$' -fuzz FuzzLoad -fuzztime 5m
```

## Adding a rule

See "Adding a rule" in [ARCHITECTURE.md](ARCHITECTURE.md). In short:

1. Ensure the snapshot contains the data, with correct collection statuses.
2. Add the rule with a unique ID (`AREA-NNN`), a severity rationale, a concrete
   remediation and https references.
3. Add table-driven tests for PASS, FAIL, SKIP and ERROR paths.
4. Regenerate `docs/rules.md` with `go test ./tests/integration -update`.

Rule IDs are never reused or renumbered once published, because baselines
refer to them.

## Commit messages

Use the imperative mood and explain *why* a change is needed, especially for
security-relevant behaviour.

## Reporting security issues

Do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
