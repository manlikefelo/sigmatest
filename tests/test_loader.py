"""Tests for rule/sample discovery and YAML loading (real filesystem via tmp_path)."""

from __future__ import annotations

import pytest

from sigmatest.errors import SigmaTestError
from sigmatest.loader import (
    default_samples_dir,
    discover_rules,
    load_yaml,
    samples_path_for,
)


def test_discover_rules_finds_yml_and_yaml(tmp_path):
    rules = tmp_path / "rules"
    (rules / "sub").mkdir(parents=True)
    (rules / "a.yml").write_text("title: a")
    (rules / "sub" / "b.yaml").write_text("title: b")
    (rules / "notes.txt").write_text("ignore me")
    found = discover_rules(rules)
    assert [p.name for p in found] == ["a.yml", "b.yaml"]


def test_discover_rules_missing_dir_raises(tmp_path):
    with pytest.raises(SigmaTestError):
        discover_rules(tmp_path / "nope")


def test_load_yaml_ok(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text("title: hi\nlevel: high")
    assert load_yaml(p) == {"title": "hi", "level": "high"}


def test_load_yaml_malformed_raises(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("title: [unclosed")
    with pytest.raises(SigmaTestError) as exc:
        load_yaml(p)
    assert "invalid YAML" in str(exc.value)


def test_load_yaml_empty_raises(tmp_path):
    p = tmp_path / "empty.yml"
    p.write_text("")
    with pytest.raises(SigmaTestError):
        load_yaml(p)


def test_load_yaml_non_mapping_raises(tmp_path):
    p = tmp_path / "list.yml"
    p.write_text("- a\n- b")
    with pytest.raises(SigmaTestError):
        load_yaml(p)


def test_samples_path_for(tmp_path):
    rule = tmp_path / "rules" / "kerb.yml"
    samples = tmp_path / "samples"
    assert samples_path_for(rule, samples) == samples / "kerb.yml"


def test_default_samples_dir_prefers_samples(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "samples").mkdir()
    (tmp_path / "tests").mkdir()
    assert default_samples_dir(tmp_path / "rules") == tmp_path / "samples"


def test_default_samples_dir_falls_back_to_tests(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "tests").mkdir()
    assert default_samples_dir(tmp_path / "rules") == tmp_path / "tests"
