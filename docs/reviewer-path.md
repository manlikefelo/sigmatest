# Reviewer path — a 3-minute guided tour

For a hiring manager or teammate seeing this repo for the first time. `sigmatest` is a
small, real, tested, packaged Python tool: it unit-tests Sigma detection rules against
sample events. Here's the fastest way to judge it.

### 1 · The test suite + CI badge first (60s)  →  `tests/` and the green badges
The centerpiece is the testing. Open the **Actions** tab: `ci` runs **ruff → mypy
(strict) → pytest** across **Python 3.11, 3.12, and 3.13**, and fails under 90%
coverage. The suite ([`tests/`](../tests/)) covers every field modifier and condition
shape plus the edge cases that actually break detections — malformed YAML, empty
samples, an unsupported modifier, a broken regex, and correlation tested at the exact
threshold boundary (15 vs. 16). 69 tests, 95% coverage.

### 2 · A usage demo (60s)  →  `sigmatest test`
```bash
pip install .
sigmatest test examples/rules --samples examples/samples
```
You'll see rules pass; break one (drop a filter) and the same command fails with a
precise message and a non-zero exit code — it drops straight into a CI gate. See the
[README](../README.md#sample-output) for sample output, and `--json` for machine output.

### 3 · The design doc (30s)  →  `docs/design.md`
[`docs/design.md`](design.md) explains the one decision that matters most: a
purpose-built offline evaluator that **fails loud rather than false-green** — it raises
on any rule it can't fully reason about, so it never claims to have tested something it
didn't. That's the difference between a real testing tool and a rubber stamp.

---
**The takeaway:** this is `pip install`-able software with a typed core, a real CLI, a
thorough test suite, and green CI on three Python versions — QA/test-automation
discipline applied to detection engineering.
