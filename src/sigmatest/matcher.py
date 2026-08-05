"""A small, dependency-light Sigma detection evaluator.

sigmatest evaluates a rule's detection logic against sample log events in pure
Python, with no live SIEM. It implements the subset of Sigma commonly used in
endpoint/AD/web detections:

  - selection maps: field -> value | list-of-values (OR within a field)
  - field modifiers: |contains, |startswith, |endswith, |re, and |all (AND over a list)
  - conditions: "selection", "a and b", "a or b", "sel and not 1 of filter_*",
    "1 of selection_*", "all of selection_*"
  - count() correlation: "selection | count() by <field> > N"

Anything outside that subset raises UnsupportedSigmaError rather than silently
passing, so an un-evaluatable rule is never treated as tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sigmatest.errors import UnsupportedSigmaError

_COUNT_RE = re.compile(r"count\(\)\s+by\s+(\w+)\s*>\s*(\d+)")
_NOT_1_OF_RE = re.compile(r"(\w+)\s+and\s+not\s+1\s+of\s+(\w+\*)")
_X_OF_RE = re.compile(r"(1|all)\s+of\s+(\w+\*)")


_VALID_MODIFIERS = frozenset({None, "contains", "startswith", "endswith", "re"})


def _compare(event_value: Any, modifier: str | None, expected: Any) -> bool:
    """Compare one event field value against one expected value + modifier.

    The modifier and expected value are validated *before* the event value is
    inspected, so a rule bug (unsupported modifier, malformed regex) is surfaced
    even when the field is absent from the event - which is what lets the linter
    catch it by dry-running against an empty event.
    """
    exp = str(expected)
    if modifier not in _VALID_MODIFIERS:
        raise UnsupportedSigmaError(f"unsupported field modifier: |{modifier}")
    if modifier == "re":
        try:
            pattern = re.compile(exp)
        except re.error as err:  # a malformed regex is a rule bug, surface it
            raise UnsupportedSigmaError(f"invalid regex in rule: {exp!r} ({err})") from err
    else:
        pattern = None

    if event_value is None:
        return False
    ev = str(event_value)

    if modifier is None:
        return ev == exp
    if modifier == "contains":
        return exp in ev
    if modifier == "startswith":
        return ev.startswith(exp)
    if modifier == "endswith":
        return ev.endswith(exp)
    assert pattern is not None  # modifier == "re"
    return pattern.search(ev) is not None


def _field_matches(event: dict[str, Any], key: str, criterion: Any) -> bool:
    """Evaluate one 'field[|modifier][|all]: value|list' entry of a selection."""
    parts = key.split("|")
    field_name = parts[0]
    modifiers = parts[1:]

    require_all = "all" in modifiers
    value_modifiers = [m for m in modifiers if m != "all"]
    if len(value_modifiers) > 1:
        raise UnsupportedSigmaError(f"multiple value modifiers not supported: {key}")
    modifier = value_modifiers[0] if value_modifiers else None

    event_value = event.get(field_name)
    expected_values = criterion if isinstance(criterion, list) else [criterion]

    results = (_compare(event_value, modifier, exp) for exp in expected_values)
    return all(results) if require_all else any(results)


def _selection_matches(event: dict[str, Any], selection: Any) -> bool:
    """A selection matches only if ALL its field entries match (AND).

    A selection may also be a LIST of maps (Sigma "list of dicts" = OR of maps).
    """
    if isinstance(selection, list):
        return any(_selection_matches(event, sub) for sub in selection)
    if not isinstance(selection, dict):
        raise UnsupportedSigmaError(f"unsupported selection type: {type(selection).__name__}")
    return all(_field_matches(event, key, crit) for key, crit in selection.items())


@dataclass
class Rule:
    """A parsed rule reduced to what the evaluator needs."""

    title: str
    detection: dict[str, Any]
    correlation: dict[str, Any] | None = None

    @property
    def is_correlation(self) -> bool:
        return self.correlation is not None


def _resolve(event: dict[str, Any], detection: dict[str, Any], name: str) -> bool:
    if name not in detection:
        raise UnsupportedSigmaError(f"condition references unknown identifier: {name}")
    return _selection_matches(event, detection[name])


def _candidates(detection: dict[str, Any], pattern: str) -> list[str]:
    prefix = pattern.rstrip("*")
    names = [k for k in detection if k != "condition" and k != "timeframe" and k.startswith(prefix)]
    if not names:
        raise UnsupportedSigmaError(f"no identifiers match pattern: {pattern}")
    return names


def _eval_condition(event: dict[str, Any], detection: dict[str, Any]) -> bool:
    """Evaluate the supported condition grammars against a single event."""
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        raise UnsupportedSigmaError("rule has no condition")

    # "<sel> and not 1 of <glob>"
    m = _NOT_1_OF_RE.fullmatch(condition)
    if m:
        sel, glob = m.group(1), m.group(2)
        return _resolve(event, detection, sel) and not any(
            _selection_matches(event, detection[c]) for c in _candidates(detection, glob)
        )

    # "1 of <glob>" / "all of <glob>"
    m = _X_OF_RE.fullmatch(condition)
    if m:
        quantifier, glob = m.group(1), m.group(2)
        matches = (_selection_matches(event, detection[c]) for c in _candidates(detection, glob))
        return any(matches) if quantifier == "1" else all(matches)

    # "a or b or ..."
    if " or " in condition and " and " not in condition and " not " not in condition:
        return any(_resolve(event, detection, t.strip()) for t in condition.split(" or "))

    # "a and b and ..."
    if " and " in condition and " not " not in condition and " of " not in condition:
        return all(_resolve(event, detection, t.strip()) for t in condition.split(" and "))

    # bare "selection"
    if re.fullmatch(r"\w+", condition):
        return _resolve(event, detection, condition)

    raise UnsupportedSigmaError(f"unsupported condition grammar: {condition!r}")


def load_rule(rule_dict: dict[str, Any]) -> Rule:
    """Turn a parsed Sigma YAML dict into a Rule, detecting count() correlation."""
    if "detection" not in rule_dict or not isinstance(rule_dict["detection"], dict):
        raise UnsupportedSigmaError("rule has no detection block")
    detection = rule_dict["detection"]
    correlation: dict[str, Any] | None = None
    m = _COUNT_RE.search(str(detection.get("condition", "")))
    if m:
        base = "selection" if "selection" in detection else None
        if base is None:
            raise UnsupportedSigmaError("count() correlation without a 'selection' base")
        correlation = {"group_by": m.group(1), "threshold": int(m.group(2)), "base": base}
    return Rule(
        title=str(rule_dict.get("title", "untitled")),
        detection=detection,
        correlation=correlation,
    )


def rule_fires(rule: Rule, events: list[dict[str, Any]]) -> bool:
    """Does this rule fire against the supplied event(s)?

    Single-event rules fire if ANY event matches the condition. Correlation rules
    fire if the count of events matching the base selection, grouped by the
    group_by field, exceeds the threshold for any group.
    """
    if rule.correlation is not None:
        base_sel = rule.detection[rule.correlation["base"]]
        group_by = rule.correlation["group_by"]
        threshold = int(rule.correlation["threshold"])
        counts: dict[str, int] = {}
        for ev in events:
            if _selection_matches(ev, base_sel):
                key = str(ev.get(group_by))
                counts[key] = counts.get(key, 0) + 1
        return any(c > threshold for c in counts.values())

    return any(_eval_condition(ev, rule.detection) for ev in events)
