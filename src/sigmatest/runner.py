"""Run a rule against its sample cases and return structured results.

Sample file schema (per rule):
    true_positives:   list of cases, each MUST make the rule fire
    benign:           list of cases, each must NOT make the rule fire

Case shapes:
    event: {...}                       a single event
    events: [ {...}, ... ]             an explicit list of events
    events: [...]  + repeat_each: N    repeat the whole list N times
    burst: { count: N, event: {...} }  N copies of one event (correlation bursts)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigmatest.errors import SampleError, UnsupportedSigmaError
from sigmatest.matcher import Rule, rule_fires


@dataclass
class SampleOutcome:
    """The result of evaluating one sample case."""

    name: str
    kind: str  # "true_positive" | "benign"
    expected_fire: bool
    actual_fire: bool
    passed: bool


@dataclass
class RuleResult:
    """Aggregate result for one rule across all its samples."""

    rule_title: str
    outcomes: list[SampleOutcome] = field(default_factory=list)
    error: str | None = None  # set when the rule could not be evaluated at all

    @property
    def passed(self) -> bool:
        return self.error is None and all(o.passed for o in self.outcomes)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def failures(self) -> list[SampleOutcome]:
        return [o for o in self.outcomes if not o.passed]


def events_from_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise any supported sample shape into a flat list of event dicts."""
    if "burst" in case:
        b = case["burst"]
        if not isinstance(b, dict) or "count" not in b or "event" not in b:
            raise SampleError(f"'burst' needs 'count' and 'event': {case!r}")
        return [dict(b["event"]) for _ in range(int(b["count"]))]
    if "events" in case:
        base = [dict(e) for e in case["events"]]
        repeat = int(case.get("repeat_each", 1))
        out: list[dict[str, Any]] = []
        for _ in range(repeat):
            out.extend(dict(e) for e in base)
        return out
    if "event" in case:
        return [dict(case["event"])]
    raise SampleError(f"sample case has no 'event', 'events', or 'burst' key: {case!r}")


def run_rule(rule: Rule, samples: dict[str, Any]) -> RuleResult:
    """Evaluate a rule against its true-positive and benign samples."""
    result = RuleResult(rule_title=rule.title)

    tps = samples.get("true_positives") or []
    benign = samples.get("benign") or []
    if not tps:
        result.error = "no true-positive samples (a rule with no tests is not trusted)"
        return result

    for kind, cases, expected in (("true_positive", tps, True), ("benign", benign, False)):
        for case in cases:
            name = str(case.get("name", "<unnamed>"))
            try:
                events = events_from_case(case)
                fired = rule_fires(rule, events)
            except (SampleError, UnsupportedSigmaError) as exc:
                result.outcomes.append(
                    SampleOutcome(name, kind, expected, actual_fire=False, passed=False)
                )
                result.error = str(exc)
                continue
            result.outcomes.append(
                SampleOutcome(name, kind, expected, actual_fire=fired, passed=fired == expected)
            )
    return result
