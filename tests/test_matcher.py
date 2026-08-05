"""Unit tests for the Sigma evaluator - field modifiers, conditions, correlation."""

from __future__ import annotations

import pytest

from sigmatest.errors import UnsupportedSigmaError
from sigmatest.matcher import _field_matches, load_rule, rule_fires


def make(detection: dict) -> object:
    return load_rule({"title": "t", "detection": detection})


# --- field modifiers ------------------------------------------------------- #
@pytest.mark.parametrize(
    ("key", "crit", "event", "expected"),
    [
        ("EventID", 4769, {"EventID": 4769}, True),
        ("EventID", 4769, {"EventID": 4624}, False),
        ("Name|contains", "sql", {"Name": "svc-sql-01"}, True),
        ("Name|contains", "sql", {"Name": "webserver"}, False),
        ("Name|startswith", "svc", {"Name": "svc-sql"}, True),
        ("Name|endswith", "$", {"Name": "WS01$"}, True),
        ("Name|endswith", "$", {"Name": "alice"}, False),
        ("Uri|re", r"(?i)union\s+select", {"Uri": "?q=UNION SELECT x"}, True),
        ("Uri|re", r"(?i)union\s+select", {"Uri": "?q=hello"}, False),
        ("Missing", "x", {"Other": "y"}, False),  # missing field never matches
    ],
)
def test_field_modifiers(key, crit, event, expected):
    assert _field_matches(event, key, crit) is expected


def test_list_value_is_or():
    assert _field_matches({"EventID": 4662}, "EventID", [4661, 4662]) is True
    assert _field_matches({"EventID": 4624}, "EventID", [4661, 4662]) is False


def test_all_modifier_is_and():
    # |all requires EVERY value in the list to match (here via contains)
    ev = {"CommandLine": "powershell -enc AAA -nop"}
    assert _field_matches(ev, "CommandLine|contains|all", ["-enc", "-nop"]) is True
    assert _field_matches(ev, "CommandLine|contains|all", ["-enc", "-missing"]) is False


def test_bad_regex_raises():
    with pytest.raises(UnsupportedSigmaError):
        _field_matches({"Uri": "x"}, "Uri|re", "([unterminated")


def test_unsupported_modifier_raises():
    with pytest.raises(UnsupportedSigmaError):
        _field_matches({"F": "x"}, "F|base64", "x")


# --- conditions ------------------------------------------------------------ #
def test_bare_selection():
    rule = make({"selection": {"EventID": 4768, "PreAuthType": "0"}, "condition": "selection"})
    assert rule_fires(rule, [{"EventID": 4768, "PreAuthType": "0"}]) is True
    assert rule_fires(rule, [{"EventID": 4768, "PreAuthType": "2"}]) is False


def test_and_not_1_of_filter():
    rule = make(
        {
            "selection": {"EventID": 4769, "Enc": "0x17"},
            "filter_machine": {"Svc|endswith": "$"},
            "filter_krbtgt": {"Svc": "krbtgt"},
            "condition": "selection and not 1 of filter_*",
        }
    )
    assert rule_fires(rule, [{"EventID": 4769, "Enc": "0x17", "Svc": "svc-sql"}]) is True
    assert rule_fires(rule, [{"EventID": 4769, "Enc": "0x17", "Svc": "WS01$"}]) is False
    assert rule_fires(rule, [{"EventID": 4769, "Enc": "0x17", "Svc": "krbtgt"}]) is False


def test_or_condition():
    rule = make(
        {
            "sqli": {"Uri|contains": "UNION SELECT"},
            "xss": {"Uri|contains": "<script"},
            "condition": "sqli or xss",
        }
    )
    assert rule_fires(rule, [{"Uri": "?q=UNION SELECT"}]) is True
    assert rule_fires(rule, [{"Uri": "?q=<script>"}]) is True
    assert rule_fires(rule, [{"Uri": "?q=hello"}]) is False


def test_and_condition():
    rule = make({"a": {"X": "1"}, "b": {"Y": "2"}, "condition": "a and b"})
    assert rule_fires(rule, [{"X": "1", "Y": "2"}]) is True
    assert rule_fires(rule, [{"X": "1", "Y": "9"}]) is False


def test_1_of_and_all_of():
    det = {"sel_a": {"X": "1"}, "sel_b": {"X": "2"}}
    r1 = make({**det, "condition": "1 of sel_*"})
    assert rule_fires(r1, [{"X": "2"}]) is True
    rall = make({**det, "condition": "all of sel_*"})
    # a single event can't be both X=1 and X=2, so all-of over exclusive sels is False
    assert rule_fires(rall, [{"X": "1"}]) is False


def test_list_of_maps_selection_is_or():
    rule = make({"selection": [{"A": "1"}, {"B": "2"}], "condition": "selection"})
    assert rule_fires(rule, [{"A": "1"}]) is True
    assert rule_fires(rule, [{"B": "2"}]) is True
    assert rule_fires(rule, [{"C": "3"}]) is False


def test_unknown_identifier_raises():
    rule = make({"selection": {"X": "1"}, "condition": "nope"})
    with pytest.raises(UnsupportedSigmaError):
        rule_fires(rule, [{"X": "1"}])


def test_empty_condition_raises():
    rule = make({"selection": {"X": "1"}, "condition": ""})
    with pytest.raises(UnsupportedSigmaError):
        rule_fires(rule, [{"X": "1"}])


# --- correlation ----------------------------------------------------------- #
def test_count_correlation_threshold():
    rule = make(
        {
            "selection": {"EventID": 4662},
            "timeframe": "60s",
            "condition": "selection | count() by User > 15",
        }
    )
    assert rule.is_correlation
    over = [{"EventID": 4662, "User": "svc"} for _ in range(16)]
    at = [{"EventID": 4662, "User": "svc"} for _ in range(15)]
    assert rule_fires(rule, over) is True
    assert rule_fires(rule, at) is False  # 15 is not > 15


def test_count_correlation_is_per_group():
    rule = make(
        {
            "selection": {"EventID": 4662},
            "condition": "selection | count() by User > 15",
        }
    )
    # 15 from userA and 15 from userB -> no single group over threshold
    events = [{"EventID": 4662, "User": "userA"} for _ in range(15)]
    events += [{"EventID": 4662, "User": "userB"} for _ in range(15)]
    assert rule_fires(rule, events) is False


def test_count_without_selection_base_raises():
    with pytest.raises(UnsupportedSigmaError):
        load_rule({"title": "t", "detection": {"foo": {"X": "1"}, "condition": "count() by U > 3"}})


def test_missing_detection_block_raises():
    with pytest.raises(UnsupportedSigmaError):
        load_rule({"title": "t"})
