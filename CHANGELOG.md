# Changelog

All notable changes to `sigmatest` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-05

Initial release.

### Added
- Offline Sigma evaluator (`sigmatest.matcher`) supporting field modifiers
  (`contains`, `startswith`, `endswith`, `re`, `all`), list-OR values, list-of-maps
  selections, the `selection and not 1 of filter_*` / `1 of x_*` / `all of x_*`
  idioms, and `count() by <field> > N` correlation.
- Sample runner (`sigmatest.runner`) with `event` / `events` / `repeat_each` /
  `burst` case shapes and structured `RuleResult` / `SampleOutcome` results.
- Structural + evaluability linter (`sigmatest.linter`).
- Rule/sample discovery and safe YAML loading (`sigmatest.loader`).
- `sigmatest` CLI with `test`, `lint`, and `list` commands, `--json` output, and
  CI-friendly exit codes (0 ok / 1 failures / 2 usage).
- Full pytest suite (95% coverage), ruff + mypy (strict) clean.
- CI across Python 3.11, 3.12, 3.13.

[Unreleased]: https://github.com/manlikefelo/sigmatest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/manlikefelo/sigmatest/releases/tag/v0.1.0
