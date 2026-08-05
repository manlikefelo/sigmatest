"""sigmatest command-line interface.

Commands:
    sigmatest test   <rules> [--samples DIR]   run TP/benign samples, fail on mismatch
    sigmatest lint   <rules>                    structural + evaluability lint
    sigmatest list   <rules> [--samples DIR]    show rules and whether they have samples

Exit codes: 0 = all good, 1 = failures/problems, 2 = usage/IO error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from sigmatest import __version__
from sigmatest.errors import SigmaTestError
from sigmatest.linter import LintProblem, lint_rule
from sigmatest.loader import (
    default_samples_dir,
    discover_rules,
    load_yaml,
    samples_path_for,
)
from sigmatest.matcher import load_rule
from sigmatest.runner import RuleResult, run_rule

app = typer.Typer(
    add_completion=False,
    help="Lint and unit-test Sigma rules against sample events - no live SIEM required.",
    no_args_is_help=True,
)

RulesArg = Annotated[Path, typer.Argument(help="A rule file or a directory of rules.")]
SamplesOpt = Annotated[
    Path | None,
    typer.Option("--samples", "-s", help="Directory of <rule-stem>.yml sample files."),
]
JsonOpt = Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sigmatest {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """sigmatest - test your detections like code."""


def _resolve_rules(rules: Path) -> list[Path]:
    if rules.is_file():
        return [rules]
    return discover_rules(rules)


def _samples_dir(rules: Path, samples: Path | None) -> Path:
    if samples is not None:
        return samples
    rules_dir = rules if rules.is_dir() else rules.parent
    return default_samples_dir(rules_dir)


@app.command()
def test(rules: RulesArg, samples: SamplesOpt = None, json_out: JsonOpt = False) -> None:
    """Run each rule against its true-positive and benign samples."""
    try:
        rule_paths = _resolve_rules(rules)
    except SigmaTestError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    if not rule_paths:
        typer.secho(f"no rules found under {rules}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(2)

    samples_dir = _samples_dir(rules, samples)
    results: list[RuleResult] = []

    for path in rule_paths:
        sp = samples_path_for(path, samples_dir)
        if not sp.exists():
            r = RuleResult(rule_title=path.stem, error=f"no samples file at {sp}")
            results.append(r)
            continue
        try:
            rule = load_rule(load_yaml(path))
            result = run_rule(rule, load_yaml(sp))
        except SigmaTestError as exc:
            result = RuleResult(rule_title=path.stem, error=str(exc))
        results.append(result)

    if json_out:
        _emit_json(rule_paths, results)
    else:
        _emit_text(rule_paths, results)

    if any(not r.passed for r in results):
        raise typer.Exit(1)


@app.command()
def lint(rules: RulesArg, json_out: JsonOpt = False) -> None:
    """Structurally lint rules and confirm the evaluator can reason about them."""
    try:
        rule_paths = _resolve_rules(rules)
    except SigmaTestError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    if not rule_paths:
        typer.secho(f"no rules found under {rules}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(2)

    payload: dict[str, Any] = {}
    failed = False
    for path in rule_paths:
        try:
            problems = lint_rule(load_yaml(path))
        except SigmaTestError as exc:
            problems = [LintProblem("error", str(exc))]
        payload[str(path)] = [{"severity": p.severity, "message": p.message} for p in problems]
        errored = any(p.severity == "error" for p in problems)
        failed = failed or errored
        if not json_out:
            if not problems:
                typer.secho(f"ok    {path}", fg=typer.colors.GREEN)
            else:
                colour = typer.colors.RED if errored else typer.colors.YELLOW
                typer.secho(f"{'FAIL' if errored else 'warn'}  {path}", fg=colour)
                for p in problems:
                    typer.echo(f"        [{p.severity}] {p.message}")

    if json_out:
        typer.echo(json.dumps(payload, indent=2))
    if failed:
        raise typer.Exit(1)


@app.command(name="list")
def list_rules(rules: RulesArg, samples: SamplesOpt = None) -> None:
    """List rules and whether each has a samples file."""
    try:
        rule_paths = _resolve_rules(rules)
    except SigmaTestError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    samples_dir = _samples_dir(rules, samples)
    for path in rule_paths:
        has = samples_path_for(path, samples_dir).exists()
        mark = "✓" if has else "✗"
        colour = typer.colors.GREEN if has else typer.colors.RED
        typer.secho(f"{mark} samples  {path}", fg=colour)
    typer.echo(f"\n{len(rule_paths)} rule(s); samples dir: {samples_dir}")


def _emit_text(rule_paths: list[Path], results: list[RuleResult]) -> None:
    total_pass = total_fail = 0
    for path, r in zip(rule_paths, results, strict=False):
        if r.passed:
            total_pass += 1
            typer.secho(f"PASS  {path.stem}  ({r.total} samples)", fg=typer.colors.GREEN)
        else:
            total_fail += 1
            typer.secho(f"FAIL  {path.stem}", fg=typer.colors.RED)
            if r.error:
                typer.echo(f"        error: {r.error}")
            for o in r.failures:
                want = "fire" if o.expected_fire else "stay quiet"
                got = "fired" if o.actual_fire else "did not fire"
                typer.echo(f"        [{o.kind}] '{o.name}': expected to {want}, but {got}")
    typer.echo("-" * 56)
    typer.secho(
        f"{total_pass} passed, {total_fail} failed",
        fg=typer.colors.GREEN if total_fail == 0 else typer.colors.RED,
    )


def _emit_json(rule_paths: list[Path], results: list[RuleResult]) -> None:
    out = []
    for path, r in zip(rule_paths, results, strict=False):
        out.append(
            {
                "rule": path.stem,
                "path": str(path),
                "passed": r.passed,
                "error": r.error,
                "samples": [
                    {"name": o.name, "kind": o.kind, "passed": o.passed, "fired": o.actual_fire}
                    for o in r.outcomes
                ],
            }
        )
    typer.echo(json.dumps({"results": out, "passed": all(r.passed for r in results)}, indent=2))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
