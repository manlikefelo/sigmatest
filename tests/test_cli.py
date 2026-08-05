"""Integration tests for the CLI via typer's CliRunner - real files, real exit codes."""

from __future__ import annotations

import json

import pytest
import yaml
from typer.testing import CliRunner

from sigmatest.cli import app

runner = CliRunner()

GOOD_RULE = {
    "title": "Kerberoast",
    "id": "6f9d0a2e-1c4b-4e77-9b0a-2a1e5c7d0011",
    "status": "stable",
    "level": "high",
    "logsource": {"product": "windows", "service": "security"},
    "detection": {
        "selection": {"EventID": 4769, "Enc": "0x17"},
        "filter_machine": {"Svc|endswith": "$"},
        "condition": "selection and not 1 of filter_*",
    },
    "tags": ["attack.t1558.003"],
}
GOOD_SAMPLES = {
    "true_positives": [
        {"name": "svc", "event": {"EventID": 4769, "Enc": "0x17", "Svc": "svc-sql"}},
    ],
    "benign": [
        {"name": "machine", "event": {"EventID": 4769, "Enc": "0x17", "Svc": "WS01$"}},
    ],
}


@pytest.fixture
def repo(tmp_path):
    rules = tmp_path / "rules"
    samples = tmp_path / "samples"
    rules.mkdir()
    samples.mkdir()
    (rules / "kerb.yml").write_text(yaml.safe_dump(GOOD_RULE))
    (samples / "kerb.yml").write_text(yaml.safe_dump(GOOD_SAMPLES))
    return tmp_path, rules, samples


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "sigmatest" in result.stdout


def test_test_command_passes(repo):
    _, rules, samples = repo
    result = runner.invoke(app, ["test", str(rules), "--samples", str(samples)])
    assert result.exit_code == 0
    assert "1 passed, 0 failed" in result.stdout


def test_test_command_autodetects_samples_dir(repo):
    _, rules, _ = repo
    # no --samples: should find sibling samples/ dir
    result = runner.invoke(app, ["test", str(rules)])
    assert result.exit_code == 0


def test_test_command_fails_on_false_positive(repo):
    _, rules, samples = repo
    # break the rule: drop the machine-account filter
    broken = {**GOOD_RULE, "detection": {**GOOD_RULE["detection"]}}
    broken["detection"].pop("filter_machine")
    broken["detection"]["condition"] = "selection"
    (rules / "kerb.yml").write_text(yaml.safe_dump(broken))
    result = runner.invoke(app, ["test", str(rules), "--samples", str(samples)])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout


def test_test_command_missing_samples_fails(repo):
    _, rules, samples = repo
    (samples / "kerb.yml").unlink()
    result = runner.invoke(app, ["test", str(rules), "--samples", str(samples)])
    assert result.exit_code == 1
    assert "no samples file" in result.stdout


def test_test_json_output(repo):
    _, rules, samples = repo
    result = runner.invoke(app, ["test", str(rules), "--samples", str(samples), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["results"][0]["rule"] == "kerb"


def test_lint_command_ok(repo):
    _, rules, _ = repo
    result = runner.invoke(app, ["lint", str(rules)])
    assert result.exit_code == 0
    assert "ok" in result.stdout


def test_lint_command_fails_on_bad_rule(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text(yaml.safe_dump({"title": "no detection"}))
    result = runner.invoke(app, ["lint", str(rules)])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout


def test_list_command(repo):
    _, rules, samples = repo
    result = runner.invoke(app, ["list", str(rules), "--samples", str(samples)])
    assert result.exit_code == 0
    assert "1 rule(s)" in result.stdout


def test_test_no_rules_found_exit_2(tmp_path):
    empty = tmp_path / "rules"
    empty.mkdir()
    result = runner.invoke(app, ["test", str(empty)])
    assert result.exit_code == 2


def test_test_single_file_argument(repo):
    _, rules, samples = repo
    result = runner.invoke(app, ["test", str(rules / "kerb.yml"), "--samples", str(samples)])
    assert result.exit_code == 0


def test_test_reports_malformed_rule(repo):
    _, rules, samples = repo
    (rules / "kerb.yml").write_text("title: [unclosed")
    result = runner.invoke(app, ["test", str(rules), "--samples", str(samples)])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout


def test_lint_json_output(repo):
    _, rules, _ = repo
    result = runner.invoke(app, ["lint", str(rules), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)


def test_lint_on_malformed_yaml(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text("title: [unclosed")
    result = runner.invoke(app, ["lint", str(rules)])
    assert result.exit_code == 1


def test_lint_missing_dir_exit_2(tmp_path):
    result = runner.invoke(app, ["lint", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_list_missing_dir_exit_2(tmp_path):
    result = runner.invoke(app, ["list", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_list_shows_missing_samples(repo):
    _, rules, samples = repo
    (samples / "kerb.yml").unlink()
    result = runner.invoke(app, ["list", str(rules), "--samples", str(samples)])
    assert result.exit_code == 0
    assert "✗" in result.stdout
