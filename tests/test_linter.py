"""Tests for the structural + evaluability linter."""

from __future__ import annotations

from sigmatest.linter import has_errors, lint_rule

GOOD = {
    "title": "Kerberoast",
    "id": "6f9d0a2e-1c4b-4e77-9b0a-2a1e5c7d0011",
    "status": "stable",
    "level": "high",
    "logsource": {"product": "windows", "service": "security"},
    "detection": {"selection": {"EventID": 4769}, "condition": "selection"},
    "tags": ["attack.credential-access", "attack.t1558.003"],
}


def test_good_rule_is_clean():
    assert lint_rule(GOOD) == []
    assert not has_errors(lint_rule(GOOD))


def test_missing_required_key_is_error():
    rule = {k: v for k, v in GOOD.items() if k != "detection"}
    problems = lint_rule(rule)
    assert has_errors(problems)
    assert any("detection" in p.message for p in problems)


def test_missing_recommended_key_is_warning_only():
    rule = {k: v for k, v in GOOD.items() if k != "status"}
    problems = lint_rule(rule)
    assert not has_errors(problems)
    assert any(p.severity == "warning" and "status" in p.message for p in problems)


def test_invalid_level_is_error():
    rule = {**GOOD, "level": "extreme"}
    problems = lint_rule(rule)
    assert has_errors(problems)
    assert any("invalid level" in p.message for p in problems)


def test_missing_attack_tag_is_error():
    rule = {**GOOD, "tags": ["some.other.tag"]}
    assert has_errors(lint_rule(rule))


def test_attack_tag_can_be_disabled():
    rule = {**GOOD, "tags": []}
    assert not has_errors(lint_rule(rule, require_attack_tag=False))


def test_unevaluatable_detection_is_error():
    rule = {**GOOD, "detection": {"selection": {"F|base64": "x"}, "condition": "selection"}}
    problems = lint_rule(rule)
    assert has_errors(problems)
    assert any("un-evaluatable" in p.message for p in problems)
