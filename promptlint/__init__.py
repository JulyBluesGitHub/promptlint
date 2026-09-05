"""promptlint — fast, local prompt-injection detection for LLM applications.

Stable public API:
    from promptlint import Firewall, ScanResult, Finding, ActionConstraints
    from promptlint import EvaluationCase, evaluate, load_corpus
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("prompt-lint-py")
except PackageNotFoundError:  # source tree without an installed distribution
    __version__ = "0.0.0+unknown"

__all__ = [
    "ActionConstraints",
    "AppContext",
    "Decision",
    "EvaluationCase",
    "EvaluationCorpus",
    "EvaluationReport",
    "Finding",
    "Firewall",
    "RiskDimension",
    "ScanResult",
    "Source",
    "Span",
    "evaluate",
    "load_builtin_corpus",
    "load_corpus",
]


def __getattr__(name: str):
    if name == "Firewall":
        from promptlint.firewall import Firewall

        return Firewall
    if name in {
        "ActionConstraints",
        "AppContext",
        "Decision",
        "Finding",
        "RiskDimension",
        "ScanResult",
        "Source",
        "Span",
    }:
        from promptlint import types as _types

        return getattr(_types, name)
    if name in {
        "EvaluationCase",
        "EvaluationCorpus",
        "EvaluationReport",
        "evaluate",
        "load_builtin_corpus",
        "load_corpus",
    }:
        from promptlint import evaluation as _evaluation

        return getattr(_evaluation, name)
    raise AttributeError(f"module 'promptlint' has no attribute {name!r}")
