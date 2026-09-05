"""Rule compiler: YAML → compiled re2/regex patterns."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

REGEX_TIMEOUT_SECONDS = 0.05


@dataclass
class CompiledRule:
    id: str
    pattern: str
    category: str
    severity: float
    description: str


def _get_regex_engine() -> tuple[Any, str, bool]:
    """Return (regex_module, engine_name, degraded).

    Priority: google-re2 → re2 → regex (fallback with timeout).
    """

    # Try google-re2 first
    try:
        import re2 as _re2

        _re2.compile("test")
        return _re2, "google-re2", False
    except ImportError:
        pass

    # Try re2 (alternate package)
    try:
        import re2 as _re2_alt

        _re2_alt.compile("test")
        return _re2_alt, "re2", False
    except ImportError:
        pass

    # Fallback to regex with timeout protection
    import regex as _regex

    log.warning(
        "re2 unavailable — using regex with %dms timeout (degraded ReDoS protection)",
        int(REGEX_TIMEOUT_SECONDS * 1000),
    )
    return _regex, "regex (fallback)", True


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    """Load rules from a YAML file. Returns list of rule dicts."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError(f"Invalid rules file: expected top-level 'rules' key in {path}")

    rules = data["rules"]
    if not isinstance(rules, list):
        raise ValueError(f"Invalid rules file: 'rules' must be a list in {path}")

    return rules


def load_builtin_rules() -> list[dict[str, Any]]:
    """Load packaged built-in rules."""
    rules_text = files("promptlint").joinpath("rules.yaml").read_text()
    data = yaml.safe_load(rules_text)
    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError("Invalid built-in rules file: expected top-level 'rules' key")
    rules = data["rules"]
    if not isinstance(rules, list):
        raise ValueError("Invalid built-in rules file: 'rules' must be a list")
    return rules


def compile_rules(
    raw_rules: list[dict[str, Any]],
) -> tuple[list[tuple[CompiledRule, Any]], str, bool]:
    """Compile raw rule dicts into (CompiledRule, compiled_regex) pairs.

    Returns (compiled_pairs, engine_name, degraded).
    """
    regex_mod, engine_name, degraded = _get_regex_engine()

    compiled = []
    seen_ids: set[str] = set()

    for raw in raw_rules:
        rule = CompiledRule(
            id=raw["id"],
            pattern=raw["pattern"],
            category=raw["category"],
            severity=float(raw["severity"]),
            description=raw.get("description", ""),
        )

        if rule.id in seen_ids:
            raise ValueError(f"Duplicate rule ID: {rule.id}")
        seen_ids.add(rule.id)

        try:
            if degraded:
                # regex module: compile with flags parsed from inline syntax
                compiled_pattern = regex_mod.compile(rule.pattern)
            else:
                compiled_pattern = regex_mod.compile(rule.pattern)
        except Exception as e:
            raise ValueError(f"Failed to compile rule {rule.id}: {e}") from e

        compiled.append((rule, compiled_pattern))

    return compiled, engine_name, degraded
