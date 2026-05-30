"""Tests for L4 policy engine."""

import pytest
from promptlint.l4 import aggregate_decisions, apply_mode, classify_tools, decide
from promptlint.types import Decision, DECISION_SEVERITY, Source


# --- Tool classification ---

def test_classify_tools_empty():
    assert classify_tools([]) == "read_only"


def test_classify_tools_read_only():
    assert classify_tools(["search", "read_file"]) == "read_only"


def test_classify_tools_write():
    assert classify_tools(["search", "shell", "read_file"]) == "write"


def test_classify_tools_elevated():
    assert classify_tools(["shell", "admin", "search"]) == "elevated"


def test_classify_tools_unknown_defaults_read_only():
    assert classify_tools(["my_custom_tool"]) == "read_only"


def test_classify_tools_custom_tiers():
    custom = {"my_tool": "elevated"}
    assert classify_tools(["search", "my_tool"], custom_tiers=custom) == "elevated"


# --- Decision bands ---

def test_decide_low_score():
    assert decide(0.10) == Decision.ALLOW


def test_decide_medium_score():
    assert decide(0.40) == Decision.ALLOW_WITH_WARNING


def test_decide_medium_quoted():
    """Heavily quoted medium-risk → ALLOW_AS_QUOTED_DATA."""
    assert decide(0.40, quoted_context=0.60) == Decision.ALLOW_AS_QUOTED_DATA


def test_decide_high_score_read_only():
    assert decide(0.70, tool_tier="read_only") == Decision.DISABLE_TOOL_CALLS


def test_decide_high_score_write():
    assert decide(0.70, tool_tier="write") == Decision.REDACT_SPANS


def test_decide_high_score_elevated():
    assert decide(0.70, tool_tier="elevated") == Decision.REQUIRE_USER_CONFIRMATION


def test_decide_critical_score():
    assert decide(0.90) == Decision.BLOCK


def test_decide_critical_elevated():
    assert decide(0.90, tool_tier="elevated") == Decision.ESCALATE_TO_HUMAN


# --- Source-based modifiers ---

def test_decide_log_source_demoted():
    """LOG source demotes critical to high."""
    decision = decide(0.90, source=Source.LOG)
    assert DECISION_SEVERITY[decision] < DECISION_SEVERITY[Decision.BLOCK]


def test_decide_retrieved_document_block_demoted():
    """Retrieved document source caps BLOCK at REQUIRE_USER_CONFIRMATION."""
    decision = decide(0.85, source=Source.RETRIEVED_DOCUMENT, tool_tier="read_only")
    assert decision != Decision.BLOCK


# --- Task explanation ---

def test_decide_task_explains_caps():
    """Task explanation caps at ALLOW_WITH_WARNING."""
    decision = decide(0.70, task_explains=True)
    assert decision == Decision.ALLOW_WITH_WARNING


# --- Mode post-filter ---

def test_apply_mode_monitor_blocks():
    """Monitor mode: BLOCK → ALLOW_WITH_WARNING."""
    assert apply_mode(Decision.BLOCK, "monitor") == Decision.ALLOW_WITH_WARNING


def test_apply_mode_monitor_escalate():
    """Monitor mode: ESCALATE → ALLOW_WITH_WARNING."""
    assert apply_mode(Decision.ESCALATE_TO_HUMAN, "monitor") == Decision.ALLOW_WITH_WARNING


def test_apply_mode_monitor_pass_through():
    """Monitor mode: non-blocking decisions pass through."""
    assert apply_mode(Decision.ALLOW_WITH_WARNING, "monitor") == Decision.ALLOW_WITH_WARNING


def test_apply_mode_paranoid_allow():
    """Paranoid mode: ALLOW → ALLOW_WITH_WARNING."""
    assert apply_mode(Decision.ALLOW, "paranoid") == Decision.ALLOW_WITH_WARNING


def test_apply_mode_block_pass_through():
    """Block mode: all decisions pass through."""
    assert apply_mode(Decision.BLOCK, "block") == Decision.BLOCK
    assert apply_mode(Decision.ALLOW, "block") == Decision.ALLOW


# --- Aggregation ---

def test_aggregate_worst_wins():
    decisions = [Decision.ALLOW, Decision.ALLOW_WITH_WARNING, Decision.BLOCK, Decision.ALLOW]
    assert aggregate_decisions(decisions) == Decision.BLOCK


def test_aggregate_empty():
    assert aggregate_decisions([]) == Decision.ALLOW


# --- End-to-end scenarios ---

def test_obvious_attack_gets_blocked():
    """High-score user_direct with write tools → BLOCK."""
    decision = decide(0.85, source=Source.USER_DIRECT, tool_tier="write")
    assert decision == Decision.BLOCK


def test_tool_output_with_shell():
    """Tool output with shell access and medium risk → appropriate handling."""
    decision = decide(0.50, source=Source.TOOL_OUTPUT, tool_tier="write")
    assert decision in (Decision.ALLOW_WITH_WARNING, Decision.ALLOW_AS_QUOTED_DATA)


def test_hard_negative_should_pass():
    """A hard negative at low score with task explanation → ALLOW."""
    decision = decide(0.10, task_explains=True)
    assert decision == Decision.ALLOW
