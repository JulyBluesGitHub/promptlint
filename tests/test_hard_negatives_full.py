"""Full pipeline tests for hard negatives — gate criteria.

Each hard negative must NOT return BLOCK, ESCALATE_TO_HUMAN,
or REQUIRE_USER_CONFIRMATION through the FULL L0->L1->L2->L4 pipeline.
Includes the jqwik debugging case which triggers PL-021 at L1 but
is rescued by L2 quoting mitigation.
"""

import pytest

from promptlint.firewall import Firewall
from promptlint.types import Decision
from tests.test_hard_negatives import FULL_PIPELINE_ONLY, HARD_NEGATIVES


@pytest.fixture(scope="module")
def fw():
    return Firewall(mode="block")


@pytest.mark.parametrize("description,text", HARD_NEGATIVES + FULL_PIPELINE_ONLY)
def test_hard_negative_full_pipeline_pass(fw, description, text):
    """Through the full pipeline, no hard negative should be blocked."""
    result = fw.scan(text)
    blocked_decisions = {
        Decision.BLOCK,
        Decision.ESCALATE_TO_HUMAN,
        Decision.REQUIRE_USER_CONFIRMATION,
    }
    assert result.decision not in blocked_decisions, (
        f"HARD NEGATIVE FAILED (full pipeline): {description}\n"
        f"Decision: {result.decision.value}\n"
        f"L4 decision: {result.l4_decision.value}\n"
        f"Risk score: {result.risk_score}\n"
        f"Text: {text[:100]}..."
    )
