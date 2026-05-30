"""promptlint — Prompt injection detection for LLM applications."""

__version__ = "0.1.0"
__all__ = ["Firewall", "ScanResult", "Span", "Decision", "Source", "AppContext"]


def __getattr__(name: str):
    if name == "Firewall":
        from promptlint.firewall import Firewall
        return Firewall
    if name in ("ScanResult", "Span", "Decision", "Source", "AppContext"):
        from promptlint import types as _types
        return getattr(_types, name)
    raise AttributeError(f"module 'promptlint' has no attribute {name!r}")
