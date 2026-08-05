"""Discovery and parsing of rules and their paired sample files.

Convention:
    <rules-dir>/**/<name>.yml     a Sigma rule
    <samples-dir>/<name>.yml      its samples: {true_positives: [...], benign: [...]}

By default the samples directory is a sibling ``samples/`` or ``tests/`` folder,
but the CLI lets the caller point at any directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sigmatest.errors import SigmaTestError

RULE_SUFFIXES = (".yml", ".yaml")


def load_yaml(path: Path) -> dict[str, Any]:
    """Parse a YAML file into a dict, with a clear error on malformed input."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SigmaTestError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SigmaTestError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        raise SigmaTestError(f"empty file: {path}")
    if not isinstance(data, dict):
        raise SigmaTestError(f"expected a YAML mapping in {path}, got {type(data).__name__}")
    return data


def discover_rules(rules_dir: Path) -> list[Path]:
    """Every .yml/.yaml rule under rules_dir, sorted for stable ordering."""
    if not rules_dir.exists():
        raise SigmaTestError(f"rules directory does not exist: {rules_dir}")
    found: list[Path] = []
    for suffix in RULE_SUFFIXES:
        found.extend(rules_dir.rglob(f"*{suffix}"))
    return sorted(set(found))


def samples_path_for(rule_path: Path, samples_dir: Path) -> Path:
    """The expected samples file for a rule (matched by filename stem)."""
    return samples_dir / f"{rule_path.stem}.yml"


def default_samples_dir(rules_dir: Path) -> Path:
    """Guess the samples directory: a sibling 'samples/' then 'tests/'."""
    for name in ("samples", "tests"):
        candidate = rules_dir.parent / name
        if candidate.is_dir():
            return candidate
    return rules_dir.parent / "samples"
