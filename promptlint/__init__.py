"""promptlint — Prompt injection detection for LLM applications.

Public API (stable, semver-governed):
    from promptlint import Firewall, ScanResult, Span, Decision, Source, AppContext
    from promptlint.middleware.fastapi import PromptlintMiddleware
    $ promptlint check "text"

Internal modules (best-effort, may change without notice):
    promptlint.l0   — canonicalization internals
    promptlint.l1   — regex engine internals
    promptlint.l2   — scoring internals
    promptlint.l4   — policy internals
    promptlint.logging — structured logging
"""

__version__ = "0.1.1"
__all__ = ["Firewall", "ScanResult", "Span", "Decision", "Source", "AppContext"]


def __getattr__(name: str):
    if name == "Firewall":
        from promptlint.firewall import Firewall
        return Firewall
    if name in ("ScanResult", "Span", "Decision", "Source", "AppContext"):
        from promptlint import types as _types
        return getattr(_types, name)
    raise AttributeError(f"module 'promptlint' has no attribute {name!r}")
