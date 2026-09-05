"""L2 contextual scorer — combines seven signals into a composite risk score.

Formula:
  score_before = max_l1_severity × 0.30
               + instruction_density × 0.15
               + destructive_verbs × 0.15
               + authority_claims × 0.15
               + encoding_suspicion × 0.15
               + semantic_shift × 0.10

  quoting_mitigation = quoted_context × 0.30  (max reduction 0.30)
  score = max(score_before - quoting_mitigation, severity_floor)

  severity_floor = max_l1_severity × 0.6  (only when L1 matched)
"""

from __future__ import annotations

from promptlint.l2.signals import (
    authority_claims,
    destructive_verbs,
    encoding_suspicion,
    instruction_density,
    quoted_context,
    semantic_shift,
    task_explains_content,
)
from promptlint.types import Annotation, L1Result, L2Result


def score(
    text: str,
    l1_result: L1Result,
    l0_annotations: list[Annotation] | None = None,
    user_task: str = "",
) -> L2Result:
    """Compute composite L2 risk score from L1 results and heuristic signals.

    Args:
        text: The canonicalized text being scanned.
        l1_result: Results from L1 regex scanning.
        l0_annotations: Annotations from L0 canonicalization.
        user_task: The user's stated task for contextual mitigation.

    Returns:
        L2Result with composite score, signal breakdown, and spans.
    """
    annotations = l0_annotations or []

    # Compute individual signals
    instr_density = instruction_density(text)
    destr_verbs = destructive_verbs(text)
    auth_score = authority_claims(text)
    enc_suspicion = encoding_suspicion(annotations)
    quote_frac = quoted_context(text, l1_result.matches)
    sem_shift = semantic_shift(text)

    # L1 contribution: use max severity from L1 matches
    l1_score = l1_result.max_severity

    # Composite score before mitigation
    score_before = (
        l1_score * 0.30
        + instr_density * 0.15
        + destr_verbs * 0.15
        + auth_score * 0.15
        + enc_suspicion * 0.15
        + sem_shift * 0.10
    )

    # Quoting mitigation — capped at 0.30
    quoting_mitigation = min(quote_frac * 0.30, 0.30)

    # Score after mitigation
    score_after = score_before - quoting_mitigation

    # Severity floor: when L1 matched, score can't go below 60% of max severity
    severity_floor = l1_score * 0.60 if l1_result.matches else 0.0
    final_score = max(score_after, severity_floor)

    # Clamp to [0, 1]
    final_score = max(0.0, min(1.0, final_score))

    return L2Result(
        score=round(final_score, 4),
        score_before_mitigation=round(score_before, 4),
        signals={
            "l1_severity": round(l1_score, 4),
            "instruction_density": round(instr_density, 4),
            "destructive_verbs": round(destr_verbs, 4),
            "authority_claims": round(auth_score, 4),
            "encoding_suspicion": round(enc_suspicion, 4),
            "quoted_context": round(quote_frac, 4),
            "semantic_shift": round(sem_shift, 4),
            "quoting_mitigation": round(quoting_mitigation, 4),
            "task_explains": 1.0 if task_explains_content(user_task, text) else 0.0,
        },
        spans=l1_result.matches,
    )
