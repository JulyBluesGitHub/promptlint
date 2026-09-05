"""Public types for promptlint. All dataclasses + enums. No Pydantic at runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Source(str, Enum):
    """Where the scanned text originated.

    Provenance metadata only: it does NOT affect L4 trust weighting.
    Indirect sources (retrieved documents, tool output, web pages, email,
    logs, model output) are treated as potentially attacker-controlled
    regardless of this label. Assert trust via AppContext.content_trust.
    """

    USER_DIRECT = "user_direct"
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_OUTPUT = "tool_output"
    WEBPAGE = "webpage"
    EMAIL = "email"
    LOG = "log"
    MODEL_OUTPUT = "model_output"
    SYSTEM_INSTRUCTION = "system_instruction"


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


class RiskDimension(str, Enum):
    """Orthogonal risk represented by a detection finding."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    PROMPT_EXTRACTION = "prompt_extraction"
    DATA_EXFILTRATION = "data_exfiltration"
    DESTRUCTIVE_ACTION = "destructive_action"
    OBFUSCATION = "obfuscation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MEMORY_MANIPULATION = "memory_manipulation"
    UNKNOWN = "unknown"

    @classmethod
    def from_category(cls, category: str) -> RiskDimension:
        mapping = {
            "instruction_override": cls.INSTRUCTION_OVERRIDE,
            "system_prompt_extraction": cls.PROMPT_EXTRACTION,
            "tool_exfiltration": cls.DATA_EXFILTRATION,
            "supply_chain_attack": cls.DESTRUCTIVE_ACTION,
            "encoding_attack": cls.OBFUSCATION,
            "delimiter_injection": cls.OBFUSCATION,
            "jailbreak": cls.PRIVILEGE_ESCALATION,
            "memory_wipe": cls.MEMORY_MANIPULATION,
        }
        return mapping.get(category, cls.UNKNOWN)


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
    category: str = ""


@dataclass(frozen=True)
class Finding:
    """Typed evidence emitted by detection, independent of enforcement."""

    rule_id: str
    category: str
    dimension: RiskDimension
    severity: float
    start: int
    end: int
    text: str
    reason: str


@dataclass(frozen=True)
class ActionConstraints:
    """Orthogonal actions callers enforce after a scan."""

    allow_model_input: bool = True
    allow_tools: bool = True
    redact_spans: bool = False
    require_confirmation: bool = False
    require_human_review: bool = False

    @classmethod
    def for_decision(cls, decision: Decision) -> ActionConstraints:
        if decision == Decision.DISABLE_TOOL_CALLS:
            return cls(allow_tools=False)
        if decision == Decision.REDACT_SPANS:
            return cls(redact_spans=True)
        if decision == Decision.REQUIRE_USER_CONFIRMATION:
            return cls(allow_model_input=False, allow_tools=False, require_confirmation=True)
        if decision == Decision.BLOCK:
            return cls(allow_model_input=False, allow_tools=False)
        if decision == Decision.ESCALATE_TO_HUMAN:
            return cls(allow_model_input=False, allow_tools=False, require_human_review=True)
        return cls()


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
    timed_out_rules: list[str] = field(default_factory=list)


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
    content_trust: str = "untrusted"


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
    findings: list[Finding] = field(default_factory=list)
    actions: ActionConstraints = field(default_factory=ActionConstraints)
    fields: dict[str, ScanResult] | None = None  # per-field when scanning multiple
    aggregate: ScanResult | None = None  # reference to aggregate when this is a sub-field
