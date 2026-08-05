"""Tests for the sample runner - case shapes, pass/fail aggregation, errors."""

from __future__ import annotations

import pytest

from sigmatest.errors import SampleError
from sigmatest.matcher import load_rule
from sigmatest.runner import events_from_case, run_rule

KERBEROAST = {
    "title": "Kerberoast",
    "detection": {
        "selection": {"EventID": 4769, "Enc": "0x17"},
        "filter_machine": {"Svc|endswith": "$"},
        "condition": "selection and not 1 of filter_*",
    },
}


def test_events_from_single_event():
    assert events_from_case({"event": {"a": 1}}) == [{"a": 1}]


def test_events_from_list():
    assert events_from_case({"events": [{"a": 1}, {"b": 2}]}) == [{"a": 1}, {"b": 2}]


def test_events_from_burst():
    out = events_from_case({"burst": {"count": 3, "event": {"a": 1}}})
    assert out == [{"a": 1}, {"a": 1}, {"a": 1}]


def test_events_repeat_each():
    out = events_from_case({"events": [{"a": 1}], "repeat_each": 2})
    assert out == [{"a": 1}, {"a": 1}]


def test_events_from_bad_case_raises():
    with pytest.raises(SampleError):
        events_from_case({"nope": 1})


def test_bad_burst_raises():
    with pytest.raises(SampleError):
        events_from_case({"burst": {"count": 3}})  # no 'event'


def test_run_rule_all_pass():
    rule = load_rule(KERBEROAST)
    samples = {
        "true_positives": [
            {"name": "svc account", "event": {"EventID": 4769, "Enc": "0x17", "Svc": "svc-sql"}}
        ],
        "benign": [
            {"name": "machine acct", "event": {"EventID": 4769, "Enc": "0x17", "Svc": "WS01$"}}
        ],
    }
    result = run_rule(rule, samples)
    assert result.passed
    assert result.total == 2
    assert result.failures == []


def test_run_rule_detects_false_positive():
    rule = load_rule(KERBEROAST)
    samples = {
        "true_positives": [{"name": "tp", "event": {"EventID": 4769, "Enc": "0x17", "Svc": "s"}}],
        # this benign is actually a machine account, which the rule correctly filters,
        # but we mislabel a REAL kerberoast as benign to force a failure:
        "benign": [
            {"name": "mislabelled", "event": {"EventID": 4769, "Enc": "0x17", "Svc": "svc"}}
        ],
    }
    result = run_rule(rule, samples)
    assert not result.passed
    assert len(result.failures) == 1
    assert result.failures[0].kind == "benign"


def test_run_rule_no_true_positives_is_error():
    rule = load_rule(KERBEROAST)
    result = run_rule(rule, {"benign": [{"name": "b", "event": {}}]})
    assert not result.passed
    assert result.error is not None
    assert "no true-positive" in result.error


def test_run_rule_reports_unnamed_case():
    rule = load_rule(KERBEROAST)
    samples = {"true_positives": [{"event": {"EventID": 4769, "Enc": "0x17", "Svc": "s"}}]}
    result = run_rule(rule, samples)
    assert result.outcomes[0].name == "<unnamed>"
