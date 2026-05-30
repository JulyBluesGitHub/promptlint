"""L4 policy engine — decision table + escalation rules + mode post-filter.

Maps composite risk scores to 8 decision levels across 4 risk bands,
with context from source, available tools, and user task.
"""

from __future__ import annotations

import logging

from promptlint.types import Decision, DECISION_SEVERITY, Source

log = logging.getLogger(__name__)

# Tool capability tiers
TOOL_TIER_UNKNOWN = "unknown"
TOOL_TIER_READ_ONLY = "read_only"
TOOL_TIER_WRITE = "write"
TOOL_TIER_NETWORK = "network"
TOOL_TIER_ELEVATED = "elevated"

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

# Warned-once registry for unknown tools
_unknown_tool_warnings: set[str] = set()


def classify_tools(
    tool_names: list[str],
    custom_tiers: dict[str, str] | None = None,
) -> str:
    """Classify the highest-risk tool tier for a set of tool names.

    Returns the most dangerous tier found among the tools.
    Unknown tools default to read_only with a one-time warning.
    """
    tiers = custom_tiers or {}
    # Merge: custom overrides default
    merged = {**DEFAULT_TOOL_TIERS, **tiers}

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
            tier = TOOL_TIER_READ_ONLY
            # Warn once for unknown tools
            if name_lower not in _unknown_tool_warnings:
                _unknown_tool_warnings.add(name_lower)
                log.warning(
                    "Unknown tool '%s' — defaulting to read_only. "
                    "Provide a custom_tiers mapping for fine-grained control.",
                    name,
                )
        if tier_rank.get(tier, 0) > tier_rank.get(highest, 0):
            highest = tier

    return highest


def decide(
    score: float,
    source: Source = Source.USER_DIRECT,
    tool_tier: str = TOOL_TIER_READ_ONLY,
    quoted_context: float = 0.0,
    task_explains: bool = False,
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
      - Task explanation mitigates (reduces severity)
      - Source trust: user_direct is most risky, log is least risky
    """
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
        if tool_tier == TOOL_TIER_ELEVATED:
            decision = Decision.ESCALATE_TO_HUMAN
        else:
            decision = Decision.BLOCK

    # Source-based escalation: user_direct is the baseline (no change)
    # Trusted sources reduce severity
    if source in (Source.LOG, Source.EMAIL):
        decision = _demote_decision(decision)
    elif source == Source.RETRIEVED_DOCUMENT and decision in (
        Decision.ESCALATE_TO_HUMAN,
        Decision.BLOCK,
    ):
        decision = Decision.REQUIRE_USER_CONFIRMATION

    # Task explanation mitigation: cap at ALLOW_WITH_WARNING
    if task_explains and DECISION_SEVERITY.get(decision, 0) > 1:
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
