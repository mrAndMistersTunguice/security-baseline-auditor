# Score methodology

The score exists so that one host can be tracked over time with a single
number. It is **not** a measure of how secure a system is, it is not comparable
between hosts with different coverage, and it is not derived from any external
standard.

## Definition

Only findings with status `PASS` or `FAIL` are counted ("evaluated rules").
`SKIP` and `ERROR` findings are excluded because their outcome is unknown.

Each evaluated finding contributes a weight based on its effective severity
(after baseline overrides):

| Severity | Weight |
|----------|--------|
| INFO     | 0 |
| LOW      | 1 |
| MEDIUM   | 2 |
| HIGH     | 4 |
| CRITICAL | 8 |

```text
score = round(100 × Σ weight(PASS) / Σ weight(PASS or FAIL))
```

If the denominator is zero (no rule evaluated, or only `INFO` rules), the score
is undefined: `null` in JSON and `n/a` in the text report.

## Why these weights

Each severity level doubles the weight of the previous one, so that one
`CRITICAL` failure outweighs several `LOW` passes. The exact values are a
judgement call; they are fixed and documented so that the number is at least
reproducible.

## How to read it

The text report always prints coverage next to the score, for example
`Score: 21/100 over 21 of 22 selected rules`. A score of 100 computed over one
evaluated rule says almost nothing. Always review the `FAIL`, `ERROR` and
`SKIP` findings themselves, and run the audit with elevated privileges for
maximum coverage.

The implementation is `summarize` in [`internal/engine/engine.go`](../internal/engine/engine.go);
the weights are tested in `internal/engine/engine_test.go`.
