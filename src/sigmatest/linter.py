"""Structural linting of Sigma rules.

sigmatest is intentionally dependency-light: it validates the structure a rule
must have to be testable, rather than pulling in the full pySigma spec engine.
The checks catch the mistakes that actually break detection content in practice:
missing detection logic, no ATT&CK mapping, an invalid severity, a broken regex,
or condition/selection syntax the evaluator cannot reason about.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sigmatest.errors import UnsupportedSigmaError
from sigmatest.matcher import load_rule, rule_fires

REQUIRED_KEYS = ("title", "logsource", "detection")
RECOMMENDED_KEYS = ("id", "status", "level")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


@dataclass
class LintProblem:
    """One problem found in a rule. severity is 'error' or 'warning'."""

    severity: str
    message: str


def lint_rule(rule_dict: dict[str, Any], *, require_attack_tag: bool = True) -> list[LintProblem]:
    """Return a list of problems for one parsed rule (empty = clean).

    Errors fail a lint run; warnings do not. Missing required keys and
    un-evaluatable detection logic are errors; missing recommended metadata is a
    warning.
    """
    problems: list[LintProblem] = []

    for key in REQUIRED_KEYS:
        if key not in rule_dict:
            problems.append(LintProblem("error", f"missing required key: '{key}'"))

    for key in RECOMMENDED_KEYS:
        if key not in rule_dict:
            problems.append(LintProblem("warning", f"missing recommended key: '{key}'"))

    level = rule_dict.get("level")
    if level is not None and level not in VALID_LEVELS:
        valid = sorted(VALID_LEVELS)
        problems.append(LintProblem("error", f"invalid level '{level}' (expected one of {valid})"))

    tags = rule_dict.get("tags", []) or []
    if require_attack_tag and not any(str(t).startswith("attack.t") for t in tags):
        problems.append(LintProblem("error", "no ATT&CK technique tag (expected 'attack.tXXXX')"))

    # The strongest check: can the evaluator actually reason about this rule?
    # We load it and dry-run its condition against an empty event. A structural
    # or syntax problem surfaces here as UnsupportedSigmaError.
    if "detection" in rule_dict:
        try:
            rule = load_rule(rule_dict)
            rule_fires(rule, [{}])
        except UnsupportedSigmaError as exc:
            problems.append(LintProblem("error", f"un-evaluatable detection: {exc}"))
        except Exception as exc:  # noqa: BLE001 - report any load failure as a lint error
            problems.append(LintProblem("error", f"could not load rule: {exc}"))

    return problems


def has_errors(problems: list[LintProblem]) -> bool:
    return any(p.severity == "error" for p in problems)
