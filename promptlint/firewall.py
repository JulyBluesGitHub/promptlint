"""Firewall facade — public API for promptlint.

Wires L0 canonicalization → L1 regex scanning → L2 scoring → L4 policy.
"""

from __future__ import annotations

import time

from promptlint.l0 import canonicalize, project_span_ranges, translate_spans
from promptlint.l1.engine import L1Engine
from promptlint.l2 import score as l2_score
from promptlint.l4 import ToolClassifier, apply_mode
from promptlint.l4 import decide as l4_decide
from promptlint.types import (
    ActionConstraints,
    AppContext,
    Decision,
    Finding,
    RiskDimension,
    ScanResult,
    Source,
    TextOutput,
)


class Firewall:
    """Prompt injection detection firewall.

    Usage:
        fw = Firewall(mode="block")
        result = fw.scan("Ignore all previous instructions")
        if result.decision == Decision.BLOCK:
            raise HTTPException(status_code=403)
    """

    def __init__(
        self,
        mode: str = "monitor",
        rules_path: str | None = None,
        tool_tiers: dict[str, str] | None = None,
        unknown_tool_tier: str = "write",
    ):
        if mode not in ("monitor", "block", "paranoid"):
            raise ValueError(f"Invalid mode: {mode!r}. Must be 'monitor', 'block', or 'paranoid'.")
        self.mode = mode
        self.tool_tiers = tool_tiers or {}
        self._tool_classifier = ToolClassifier(
            self.tool_tiers,
            unknown_tier=unknown_tool_tier,
        )
        self._engine = L1Engine(rules_path=rules_path)

    @property
    def engine_name(self) -> str:
        return self._engine.engine_name

    @property
    def degraded(self) -> bool:
        return self._engine.degraded

    @property
    def rule_count(self) -> int:
        return self._engine.rule_count

    def scan(
        self,
        text: str,
        source: str = "user_direct",
        app_context: AppContext | None = None,
    ) -> ScanResult:
        """Scan text for prompt injection attacks.

        Args:
            text: The input text to scan.
            source: Where the text originated (user_direct, tool_output, etc.).
            app_context: Optional application context for scoring.

        Returns:
            ScanResult with decision, risk_score, spans, and processed text.
        """
        t0 = time.perf_counter()
        ctx = app_context or AppContext()

        # Parse source — fail loudly on invalid source values
        try:
            source_enum = Source(source)
        except ValueError:
            raise ValueError(
                f"Invalid source: {source!r}. Must be one of: {', '.join(s.value for s in Source)}"
            ) from None

        # L0: Canonicalization
        t_l0_start = time.perf_counter()
        l0_result = canonicalize(text)
        t_l0 = time.perf_counter() - t_l0_start

        # L1: Regex scanning
        t_l1_start = time.perf_counter()
        l1_result = self._engine.scan(l0_result.normalized)
        t_l1 = time.perf_counter() - t_l1_start

        # L2: Contextual scoring
        t_l2_start = time.perf_counter()
        l2_result = l2_score(
            l0_result.normalized,
            l1_result,
            l0_annotations=l0_result.annotations,
            user_task=ctx.user_task,
        )
        t_l2 = time.perf_counter() - t_l2_start

        # L4: Policy decision
        tool_tier = self._tool_classifier.classify(ctx.available_tools)
        quoted_frac = l2_result.signals.get("quoted_context", 0.0)
        task_explains = l2_result.signals.get("task_explains", 0.0) > 0.0

        l4_decision = l4_decide(
            score=l2_result.score,
            source=source_enum,
            tool_tier=tool_tier,
            quoted_context=quoted_frac,
            task_explains=task_explains,
            content_trust=ctx.content_trust,
        )

        # Apply mode post-filter
        decision = apply_mode(l4_decision, self.mode)

        # Produce safe text based on decision
        translated_spans = translate_spans(l0_result, l1_result.matches)
        original_ranges = project_span_ranges(l0_result, l1_result.matches)
        safe_text = self._produce_safe_text(
            text,
            decision,
            original_ranges,
        )
        findings = [
            Finding(
                rule_id=rule_id,
                category=span.category,
                dimension=RiskDimension.from_category(span.category),
                severity=span.risk_score,
                start=span.start,
                end=span.end,
                text=span.text,
                reason=span.reason,
            )
            for span in translated_spans
            for rule_id in span.matched_rules
        ]

        total_time = time.perf_counter() - t0

        return ScanResult(
            decision=decision,
            l4_decision=l4_decision,
            risk_score=l2_result.score,
            mode=self.mode,
            text=TextOutput(original=text, safe=safe_text),
            spans=translated_spans,
            l0=l0_result,
            l1=l1_result,
            l2=l2_result,
            diagnostics={
                "engine": self._engine.engine_name,
                "degraded": self._engine.degraded,
                "rule_count": self._engine.rule_count,
                "tool_tier": tool_tier,
                "timing_ms": {
                    "total": round(total_time * 1000, 2),
                    "l0": round(t_l0 * 1000, 2),
                    "l1": round(t_l1 * 1000, 2),
                    "l2": round(t_l2 * 1000, 2),
                },
            },
            findings=findings,
            actions=ActionConstraints.for_decision(decision),
        )

    def _produce_safe_text(
        self,
        original: str,
        decision: Decision,
        ranges: list[tuple[int, int]],
    ) -> str:
        """Produce safe text output based on decision."""
        if decision == Decision.ALLOW:
            return original
        elif decision == Decision.ALLOW_WITH_WARNING:
            return original  # text is passed through, warning is in metadata
        elif decision == Decision.ALLOW_AS_QUOTED_DATA:
            return self._quote_ranges(original, ranges)
        elif decision == Decision.REDACT_SPANS:
            return self._redact_ranges(original, ranges)
        elif decision == Decision.BLOCK:
            return "[BLOCKED]"
        elif decision == Decision.ESCALATE_TO_HUMAN:
            return "[ESCALATED]"
        elif decision == Decision.DISABLE_TOOL_CALLS:
            return original  # text unchanged, tools disabled externally
        elif decision == Decision.REQUIRE_USER_CONFIRMATION:
            return original  # text unchanged, confirmation required externally
        return original

    @staticmethod
    def _quote_ranges(text: str, ranges: list[tuple[int, int]]) -> str:
        """Wrap matched spans in markdown blockquotes."""
        if not ranges:
            return text
        # Sort spans in reverse order to avoid index shifting
        sorted_ranges = sorted(ranges, key=lambda r: r[0], reverse=True)
        result = text
        for start, end in sorted_ranges:
            result = result[:start] + "\n> " + result[start:end] + "\n" + result[end:]
        return result

    @staticmethod
    def _redact_ranges(text: str, ranges: list[tuple[int, int]]) -> str:
        """Replace matched spans with [REDACTED]."""
        if not ranges:
            return text
        sorted_ranges = sorted(ranges, key=lambda r: r[0], reverse=True)
        result = text
        for start, end in sorted_ranges:
            result = result[:start] + "[REDACTED]" + result[end:]
        return result
