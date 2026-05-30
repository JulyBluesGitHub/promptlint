"""Full pipeline tests for attack cases — gate criteria.

Each attack must score >0.5 and produce L4 decision >= ALLOW_WITH_WARNING
through the FULL L0→L1→L2→L4 pipeline.
"""

import pytest
from promptlint.firewall import Firewall
from promptlint.types import Decision, DECISION_SEVERITY

from tests.test_attack_rules import ATTACK_CASES


@pytest.fixture(scope="module")
def fw():
    return Firewall(mode="block")


@pytest.mark.parametrize("rule_id,text,min_severity", ATTACK_CASES)
def test_attack_full_pipeline_concern(fw, rule_id, text, min_severity):
    """Each attack through full pipeline should raise concern."""
    result = fw.scan(text)
    assert result.risk_score >= 0.45, (
        f"Attack {rule_id} score {result.risk_score} below 0.45 threshold\n"
        f"L4 decision: {result.l4_decision.value}\n"
        f"Spans: {len(result.spans)}"
    )
    assert DECISION_SEVERITY[result.l4_decision] >= DECISION_SEVERITY[Decision.ALLOW_WITH_WARNING], (
        f"Attack {rule_id} L4 decision {result.l4_decision.value} below ALLOW_WITH_WARNING\n"
        f"Score: {result.risk_score}"
    )
