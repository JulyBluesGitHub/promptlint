"""Public types for promptlint. All dataclasses + enums. No Pydantic at runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Source(str, Enum):
    """Where the scanned text originated. Affects L4 trust weighting."""
    USER_DIRECT = "user_direct"
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_OUTPUT = "tool_output"
    WEBPAGE = "webpage"
    EMAIL = "email"
    LOG = "log"


class Decision(str, Enum):
    """L4 policy decision, ordered least to most restrictive."""
    ALLOW = "ALLOW"
    ALLOW_WITH_WARNING = "ALLOW_WITH_WARNING"
    ALLOW_AS_QUOTED_DATA = "ALLOW_AS_QUOTED_DATA"
    DISABLE_TOOL_CALLS = "DISABLE_TOOL_CALLS"
    REDACT_SPANS = "REDACT_SPANS"
    REQUIRE_USER_CONFIRMATION = "REQUIRE_USER_CONFIRMATION"
    BLOCK = "BLOCK"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


# Severity order for aggregation — higher index = more restrictive
DECISION_SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.ALLOW_WITH_WARNING: 1,
    Decision.ALLOW_AS_QUOTED_DATA: 2,
    Decision.DISABLE_TOOL_CALLS: 3,
    Decision.REDACT_SPANS: 4,
    Decision.REQUIRE_USER_CONFIRMATION: 5,
    Decision.BLOCK: 6,
    Decision.ESCALATE_TO_HUMAN: 7,
}


@dataclass
class Span:
    """A detected suspicious region in the input text."""
    start: int
    end: int
    text: str
    risk_score: float
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    source: Source | None = None


@dataclass
class Annotation:
    """L0 canonicalization finding — not necessarily a risk, but noted."""
    type: str  # "zero_width_chars", "ansi_escape", "bidi_control", "url_encoded", etc.
    start: int
    end: int
    detail: str = ""


@dataclass
class CanonicalizationResult:
    """Output from L0 canonicalization."""
    original: str
    normalized: str
    offset_map: list[tuple[int, int]]  # (canonical_pos, original_pos)
    annotations: list[Annotation] = field(default_factory=list)
    truncated: bool = False


@dataclass
class L1Result:
    """Output from L1 regex scanning."""
    matches: list[Span] = field(default_factory=list)
    max_severity: float = 0.0
    engine: str = ""
    engine_degraded: bool = False


@dataclass
class L2Result:
    """Output from L2 contextual scoring."""
    score: float  # 0.0–1.0 composite
    score_before_mitigation: float
    signals: dict[str, float] = field(default_factory=dict)
    spans: list[Span] = field(default_factory=list)


@dataclass
class AppContext:
    """Application context for contextual scoring and policy decisions."""
    available_tools: list[str] = field(default_factory=list)
    user_task: str = ""


@dataclass
class TextOutput:
    """Processed text variants from scan."""
    original: str
    safe: str  # redacted/quoted as needed for current decision


@dataclass
class ScanResult:
    """Complete result from firewall.scan()."""
    decision: Decision
    l4_decision: Decision  # raw L4 decision before mode filtering
    risk_score: float
    mode: str
    text: TextOutput
    spans: list[Span] = field(default_factory=list)
    l0: CanonicalizationResult | None = None
    l1: L1Result | None = None
    l2: L2Result | None = None
    diagnostics: dict = field(default_factory=dict)
    fields: dict[str, "ScanResult"] | None = None  # per-field when scanning multiple
    aggregate: "ScanResult | None" = None  # reference to aggregate when this is a sub-field
