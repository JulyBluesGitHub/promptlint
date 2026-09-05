"""Tests for L4 policy engine."""

import logging

import pytest

from promptlint.l4 import (
    ToolClassifier,
    aggregate_decisions,
    apply_mode,
    classify_tools,
    decide,
    validate_tool_tiers,
)
from promptlint.types import Decision, Source

# --- Tool classification ---


def test_classify_tools_empty():
    assert classify_tools([]) == "read_only"


def test_classify_tools_read_only():
    assert classify_tools(["search", "read_file"]) == "read_only"


def test_classify_tools_write():
    assert classify_tools(["search", "shell", "read_file"]) == "write"


def test_classify_tools_elevated():
    assert classify_tools(["shell", "admin", "search"]) == "elevated"


def test_classify_tools_unknown_defaults_write():
    assert classify_tools(["my_custom_tool"]) == "write"


def test_classify_tools_custom_tiers():
    custom = {"my_tool": "elevated"}
    assert classify_tools(["search", "my_tool"], custom_tiers=custom) == "elevated"


def test_validate_tool_tiers_rejects_invalid_tier():
    with pytest.raises(ValueError, match="eleveated"):
        validate_tool_tiers({"my_tool": "eleveated"})


def test_classify_tools_invalid_custom_tier_raises():
    with pytest.raises(ValueError, match="eleveated"):
        classify_tools(["my_tool"], custom_tiers={"my_tool": "eleveated"})


def test_classify_tools_normalizes_custom_tool_names():
    assert classify_tools(["my_tool"], custom_tiers={"MY_TOOL": "write"}) == "write"


def test_tool_classifier_unknown_warning_state_is_instance_local(caplog):
    caplog.set_level(logging.WARNING, logger="promptlint.l4.policy")

    first = ToolClassifier()
    first.classify(["mystery_tool"])
    first.classify(["mystery_tool"])

    first_warnings = [record for record in caplog.records if "mystery_tool" in record.getMessage()]
    assert len(first_warnings) == 1

    caplog.clear()
    second = ToolClassifier()
    second.classify(["mystery_tool"])

    second_warnings = [record for record in caplog.records if "mystery_tool" in record.getMessage()]
    assert len(second_warnings) == 1


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


def test_decide_log_source_is_not_implicitly_trusted():
    """Logs can carry indirect injection and must not reduce severity."""
    decision = decide(0.90, source=Source.LOG)
    assert decision == Decision.BLOCK


def test_decide_retrieved_document_is_not_implicitly_trusted():
    """Retrieved documents are an indirect-injection surface."""
    decision = decide(0.85, source=Source.RETRIEVED_DOCUMENT, tool_tier="read_only")
    assert decision == Decision.BLOCK


# --- Task explanation ---


def test_decide_task_explanation_alone_does_not_cap():
    """An explanation cue without quoted evidence is not a mitigation."""
    decision = decide(0.70, task_explains=True)
    assert decision == Decision.DISABLE_TOOL_CALLS


def test_decide_quoted_task_explanation_mitigates_noncritical_content():
    decision = decide(0.70, task_explains=True, quoted_context=0.75)
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


@pytest.mark.parametrize(
    "source",
    [Source.RETRIEVED_DOCUMENT, Source.TOOL_OUTPUT, Source.WEBPAGE, Source.EMAIL, Source.LOG],
)
def test_untrusted_indirect_sources_never_demote_critical_risk(source):
    """Attacker-controlled indirect content must not be treated as trusted."""
    assert decide(0.90, source=source) == Decision.BLOCK


def test_task_explanation_cannot_downgrade_critical_risk():
    """A text-controlled explanation cue is not a security waiver."""
    assert decide(0.90, task_explains=True) == Decision.BLOCK


def test_unknown_tools_default_to_write_capability():
    """Unknown capabilities must fail conservatively."""
    assert classify_tools(["write_file"]) == "write"


def test_explicit_trusted_content_can_be_demoted_once():
    """Only an explicit trust assertion may reduce a policy decision."""
    assert decide(0.90, content_trust="trusted") == Decision.REQUIRE_USER_CONFIRMATION
