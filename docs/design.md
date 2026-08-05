# Design notes

## The problem it solves

Detection rules are usually written and never tested. You can't tell whether a rule
still fires on the thing it's meant to catch, or whether it's quietly alerting on
benign traffic — until it fails in production. Existing Sigma tooling (pySigma /
sigma-cli) is excellent at *converting* rules to backend queries, but it doesn't
*evaluate* a rule against sample events. That gap is exactly the one a QA engineer
notices: there's no unit test for the detection.

`sigmatest` fills it. Point it at a folder of rules and a folder of sample events; it
tells you, per rule, whether the true positives fire and the benign look-alikes stay
quiet — in seconds, with no SIEM.

## Key decisions

**A purpose-built evaluator, not pySigma.** pySigma compiles to queries; running those
queries needs a live backend. To keep the tool fast, offline, and dependency-light
(just `pyyaml` + `typer`), `sigmatest` implements the Sigma subset that real
endpoint/AD/web rules use. The trade-off is honest: it's a *subset*. Anything outside
it raises `UnsupportedSigmaError` rather than silently passing, so the tool never
claims to have tested a rule it couldn't actually reason about. That "fail loud, never
false-green" rule is the single most important design choice — a testing tool that
lies about coverage is worse than none.

**Structured results, not just exit codes.** `run_rule` returns `RuleResult` objects
with per-sample outcomes, so the same core drives the human-readable CLI table, the
`--json` output for CI, and the library API. The CLI is a thin presentation layer over
a typed core.

**`src/` layout + strict typing.** The package uses a `src/` layout so tests run
against the installed package, not the working tree, and `mypy --strict` runs in CI.
This is deliberately "boring, production-grade Python" — the point of the project is to
show the engineering, not clever tricks.

**Coverage as a gate.** CI fails under 90% coverage (`--cov-fail-under=90`). The suite
targets the behaviour that matters: every field modifier, every condition shape,
correlation at the threshold *boundary* (15 vs. 16), and the messy edge cases —
malformed YAML, empty samples, an unsupported modifier, a broken regex, a missing
samples file.

## How it fits the portfolio

This tool was extracted from my [detection-as-code](https://github.com/manlikefelo/detection-as-code)
project (P5), where the same matcher lived as an internal test helper. Promoting it to
a standalone, packaged, pip-installable tool is the "custom Python tooling" capstone
(P10): it's the thing I wished existed while doing the earlier detection work, built to
the standard a team would actually depend on.

- **detection-as-code** could import `sigmatest` instead of vendoring its own matcher.
- The rules it tests originate in **detection-engineering** (P2).
- Part of the pinned **[cybersecurity-portfolio](https://github.com/manlikefelo/cybersecurity-portfolio)** meta-repo.

The through-line: I bring software-engineering rigor — testing, typing, CI, packaging —
to security work. `sigmatest` is that sentence as a runnable artifact.

## Possible future work
- A `convert` command wrapping pySigma backends (opt-in dependency).
- More Sigma modifiers (`base64`, `cidr`, `|lt`/`|gt`) as rules need them.
- A pytest plugin so `sigmatest` cases run as native pytest items.
