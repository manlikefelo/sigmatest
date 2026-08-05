# sigmatest

**Lint and unit-test your Sigma detection rules against sample log events — no live SIEM required.**

![CI](https://github.com/manlikefelo/sigmatest/actions/workflows/ci.yml/badge.svg)
![coverage](docs/coverage.svg)
![python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue)
![license](https://img.shields.io/badge/license-MIT-green)

`sigmatest` treats detection rules the way you'd treat application code: it runs each rule against **true-positive events that must alert** and **benign events that must not**, and fails when a rule gets it wrong. It's a small, fast, pure-Python evaluator — the tests run in seconds on a stock CI runner with no SIEM to stand up.

I built this while putting my Sigma rules under CI in my [detection-as-code](https://github.com/manlikefelo/detection-as-code) project — the matcher there wanted to be a real, reusable, packaged tool. This is that tool, engineered to production standards: `src` layout, a typed API, a typer CLI, a thorough pytest suite, and CI running ruff + mypy + tests across three Python versions.

---

## Install

```bash
pip install sigmatest        # from PyPI (once published)
# or, from a clone:
pip install .
```

Requires Python 3.11+. Runtime deps are just `pyyaml` and `typer`.

## Usage

```bash
sigmatest test   rules/                 # run every rule against its samples
sigmatest lint   rules/                 # structural + evaluability lint
sigmatest list   rules/ --samples tests/  # show which rules have samples
sigmatest test   rules/ --json          # machine-readable output for CI
```

### The convention

```
rules/**/<name>.yml     a Sigma rule
samples/<name>.yml      its samples, matched by filename stem
```

A samples file pairs each rule with events:

```yaml
true_positives:
  - name: RC4 service ticket for a real service account
    event: { EventID: 4769, TicketEncryptionType: "0x17", ServiceName: "svc-sql" }
benign:
  - name: same ticket for a machine account - must NOT fire
    event: { EventID: 4769, TicketEncryptionType: "0x17", ServiceName: "WS01$" }
```

Case shapes: a single `event`, an `events` list (with optional `repeat_each`), or a
`burst: {count, event}` for testing `count()` correlation rules.

### Sample output

```
$ sigmatest test examples/rules --samples examples/samples
PASS  kerberoasting_rc4_tgs  (5 samples)
PASS  bloodhound_burst       (3 samples)
FAIL  broken_kerberoast
        [benign] 'machine account WS01$': expected to stay quiet, but fired
--------------------------------------------------------
2 passed, 1 failed
$ echo $?
1
```

Exit codes: **0** all good · **1** failures/lint problems · **2** usage/IO error — so it drops straight into a CI gate.

## What it understands

Field modifiers `contains` / `startswith` / `endswith` / `re` / `all`; list values (OR);
`selection`, `a and b`, `a or b`, `sel and not 1 of filter_*`, `1 of x_*`, `all of x_*`;
and `count() by <field> > N` correlation. Anything outside that subset raises
`UnsupportedSigmaError` rather than silently passing — an un-evaluatable rule is never
reported as tested.

## Library API

```python
from sigmatest import load_rule, run_rule, lint_rule
import yaml

rule = load_rule(yaml.safe_load(open("rules/kerberoast.yml")))
result = run_rule(rule, yaml.safe_load(open("samples/kerberoast.yml")))
print(result.passed, [o.name for o in result.failures])
```

## Showcase

- **The test suite is the centerpiece** — see [`tests/`](tests/) and the coverage badge above. Unit tests for every field modifier and condition shape, plus edge cases: malformed YAML, empty samples, an unsupported modifier, a broken regex, correlation at the threshold boundary.
- **Green CI across 3.11 / 3.12 / 3.13** with ruff + mypy (`--strict`) + pytest — [`ci.yml`](.github/workflows/ci.yml).
- **A real CLI**: `pip install` it and `sigmatest test rules/` in any detection repo.

## Development

```bash
pip install -e ".[dev]"
ruff check .
mypy src
pytest --cov=sigmatest --cov-report=term-missing
```

See [`docs/design.md`](docs/design.md) for design decisions and how this fits the rest of my portfolio, and [`CHANGELOG.md`](CHANGELOG.md) for versions.

## License

MIT © 2026 Felix Githure
