"""L4 policy engine — decision table + escalation rules + mode post-filter.

Maps composite risk scores to 8 decision levels across 4 risk bands,
with context from source, available tools, and user task.
"""

from __future__ import annotations

import logging

from promptlint.types import DECISION_SEVERITY, Decision, Source

log = logging.getLogger(__name__)

# Tool capability tiers
TOOL_TIER_READ_ONLY = "read_only"
TOOL_TIER_WRITE = "write"
TOOL_TIER_NETWORK = "network"
TOOL_TIER_ELEVATED = "elevated"
ALLOWED_TOOL_TIERS = {
    TOOL_TIER_READ_ONLY,
    TOOL_TIER_NETWORK,
    TOOL_TIER_WRITE,
    TOOL_TIER_ELEVATED,
}

CONTENT_TRUST_UNTRUSTED = "untrusted"
CONTENT_TRUST_TRUSTED = "trusted"
ALLOWED_CONTENT_TRUST = {CONTENT_TRUST_UNTRUSTED, CONTENT_TRUST_TRUSTED}

# Default classification: common tool names → tier
DEFAULT_TOOL_TIERS: dict[str, str] = {
    "filesystem": TOOL_TIER_WRITE,
    "shell": TOOL_TIER_WRITE,
    "terminal": TOOL_TIER_WRITE,
    "bash": TOOL_TIER_WRITE,
    "python": TOOL_TIER_WRITE,
    "code_exec": TOOL_TIER_WRITE,
    "browser": TOOL_TIER_NETWORK,
    "web": TOOL_TIER_NETWORK,
    "email": TOOL_TIER_NETWORK,
    "api": TOOL_TIER_NETWORK,
    "database": TOOL_TIER_WRITE,
    "db": TOOL_TIER_WRITE,
    "sql": TOOL_TIER_WRITE,
    "file": TOOL_TIER_WRITE,
    "write_file": TOOL_TIER_WRITE,
    "patch": TOOL_TIER_WRITE,
    "http": TOOL_TIER_NETWORK,
    "git": TOOL_TIER_WRITE,
    "docker": TOOL_TIER_ELEVATED,
    "sudo": TOOL_TIER_ELEVATED,
    "admin": TOOL_TIER_ELEVATED,
    "payment": TOOL_TIER_ELEVATED,
    "search": TOOL_TIER_READ_ONLY,
    "read_file": TOOL_TIER_READ_ONLY,
    "grep": TOOL_TIER_READ_ONLY,
}


def validate_tool_tiers(custom_tiers: dict[str, str] | None) -> dict[str, str]:
    """Validate and normalize custom tool tier mappings."""
    if not custom_tiers:
        return {}

    normalized: dict[str, str] = {}
    for tool_name, tier in custom_tiers.items():
        if tier not in ALLOWED_TOOL_TIERS:
            allowed = ", ".join(sorted(ALLOWED_TOOL_TIERS))
            raise ValueError(
                f"Invalid tier {tier!r} for tool {tool_name!r}. Allowed tiers: {allowed}."
            )
        normalized[tool_name.lower()] = tier
    return normalized


class ToolClassifier:
    """Classify available tools with per-instance unknown-tool warning state."""

    def __init__(
        self,
        custom_tiers: dict[str, str] | None = None,
        unknown_tier: str = TOOL_TIER_WRITE,
    ):
        self.custom_tiers = validate_tool_tiers(custom_tiers)
        if unknown_tier not in ALLOWED_TOOL_TIERS:
            allowed = ", ".join(sorted(ALLOWED_TOOL_TIERS))
            raise ValueError(f"Invalid unknown_tier: {unknown_tier!r}. Allowed tiers: {allowed}.")
        self.unknown_tier = unknown_tier
        self._unknown_tool_warnings: set[str] = set()

    def classify(self, tool_names: list[str]) -> str:
        """Return the highest-risk tier for the supplied tool names."""
        merged = {**DEFAULT_TOOL_TIERS, **self.custom_tiers}
        highest = TOOL_TIER_READ_ONLY  # default for empty set
        tier_rank = {
            TOOL_TIER_READ_ONLY: 0,
            TOOL_TIER_NETWORK: 1,
            TOOL_TIER_WRITE: 2,
            TOOL_TIER_ELEVATED: 3,
        }

        for name in tool_names:
            name_lower = name.lower()
            if name_lower in merged:
                tier = merged[name_lower]
            else:
                tier = self.unknown_tier
                if name_lower not in self._unknown_tool_warnings:
                    self._unknown_tool_warnings.add(name_lower)
                    log.warning(
                        "Unknown tool '%s' — defaulting to %s. "
                        "Provide a custom_tiers mapping for fine-grained control.",
                        name,
                        self.unknown_tier,
                    )
            if tier_rank.get(tier, 0) > tier_rank.get(highest, 0):
                highest = tier

        return highest


def classify_tools(
    tool_names: list[str],
    custom_tiers: dict[str, str] | None = None,
    unknown_tier: str = TOOL_TIER_WRITE,
) -> str:
    """Classify the highest-risk tool tier for a set of tool names.

    Returns the most dangerous tier found among the tools.
    Unknown tools default to write with warning state owned by the classifier.
    """
    return ToolClassifier(custom_tiers, unknown_tier=unknown_tier).classify(tool_names)


def decide(
    score: float,
    source: Source = Source.USER_DIRECT,
    tool_tier: str = TOOL_TIER_READ_ONLY,
    quoted_context: float = 0.0,
    task_explains: bool = False,
    content_trust: str = CONTENT_TRUST_UNTRUSTED,
) -> Decision:
    """Map a composite risk score to a policy decision.

    Decision bands:
      - 0.00–0.30: Low risk — ALLOW
      - 0.30–0.60: Medium risk — ALLOW_WITH_WARNING / ALLOW_AS_QUOTED_DATA
      - 0.60–0.80: High risk — DISABLE_TOOL_CALLS / REDACT_SPANS / REQUIRE_USER_CONFIRMATION
      - 0.80–1.00: Critical — BLOCK / ESCALATE_TO_HUMAN

    Modifiers:
      - High tool tier (elevated) escalates decision
      - Quoted context mitigates (reduces severity)
      - Task explanation only mitigates quoted, non-critical content
      - Source records provenance but never implies trust
      - Explicit trusted content may reduce one decision level
    """
    if tool_tier not in ALLOWED_TOOL_TIERS:
        allowed = ", ".join(sorted(ALLOWED_TOOL_TIERS))
        raise ValueError(f"Invalid tool_tier: {tool_tier!r}. Must be one of: {allowed}")

    if content_trust not in ALLOWED_CONTENT_TRUST:
        allowed = ", ".join(sorted(ALLOWED_CONTENT_TRUST))
        raise ValueError(f"Invalid content_trust: {content_trust!r}. Must be one of: {allowed}")

    # Base decision from score band
    if score < 0.30:
        decision = Decision.ALLOW
    elif score < 0.60:
        # Medium band: prefer warning unless heavily quoted
        if quoted_context >= 0.50:
            decision = Decision.ALLOW_AS_QUOTED_DATA
        else:
            decision = Decision.ALLOW_WITH_WARNING
    elif score < 0.80:
        # High band
        if tool_tier == TOOL_TIER_READ_ONLY:
            decision = Decision.DISABLE_TOOL_CALLS
        elif tool_tier == TOOL_TIER_ELEVATED:
            decision = Decision.REQUIRE_USER_CONFIRMATION
        else:
            decision = Decision.REDACT_SPANS
    else:
        # Critical band
        decision = Decision.ESCALATE_TO_HUMAN if tool_tier == TOOL_TIER_ELEVATED else Decision.BLOCK

    # Source describes provenance, not trust. Indirect content is frequently
    # attacker-controlled, so only an explicit trust assertion can demote.
    if content_trust == CONTENT_TRUST_TRUSTED and decision != Decision.ALLOW:
        decision = _demote_decision(decision)

    # Explanatory context is weak evidence: it only mitigates quoted,
    # non-critical content and can never waive a critical finding.
    if (
        task_explains
        and quoted_context >= 0.50
        and score < 0.80
        and DECISION_SEVERITY.get(decision, 0) > 1
    ):
        decision = Decision.ALLOW_WITH_WARNING

    return decision


def _demote_decision(decision: Decision) -> Decision:
    """Move decision one level less restrictive."""
    levels = [
        Decision.ALLOW,
        Decision.ALLOW_WITH_WARNING,
        Decision.ALLOW_AS_QUOTED_DATA,
        Decision.DISABLE_TOOL_CALLS,
        Decision.REDACT_SPANS,
        Decision.REQUIRE_USER_CONFIRMATION,
        Decision.BLOCK,
        Decision.ESCALATE_TO_HUMAN,
    ]
    idx = levels.index(decision) if decision in levels else 0
    new_idx = max(0, idx - 1)
    return levels[new_idx]


def apply_mode(decision: Decision, mode: str) -> Decision:
    """Post-filter L4 decision based on operational mode.

    Modes:
      - monitor: never block, report only — maps BLOCK/ESCALATE to ALLOW_WITH_WARNING
      - block: normal operation — passes through all decisions
      - paranoid: escalated operation — maps ALLOW and ALLOW_WITH_WARNING up one level
    """
    if mode == "monitor":
        if decision in (Decision.BLOCK, Decision.ESCALATE_TO_HUMAN):
            return Decision.ALLOW_WITH_WARNING
        return decision
    elif mode == "paranoid":
        if decision == Decision.ALLOW:
            return Decision.ALLOW_WITH_WARNING
        if decision == Decision.ALLOW_WITH_WARNING:
            return Decision.ALLOW_AS_QUOTED_DATA
        return decision
    else:
        # block mode (default): pass through
        return decision


def aggregate_decisions(decisions: list[Decision]) -> Decision:
    """Return the most restrictive decision from a list (worst wins)."""
    if not decisions:
        return Decision.ALLOW
    return max(decisions, key=lambda d: DECISION_SEVERITY.get(d, 0))
