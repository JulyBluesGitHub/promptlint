"""L1 regex scanning engine."""

from __future__ import annotations

import logging

from promptlint.l1.compiler import (
    REGEX_TIMEOUT_SECONDS,
    CompiledRule,
    compile_rules,
    load_builtin_rules,
    load_rules,
)
from promptlint.types import L1Result, Span

log = logging.getLogger(__name__)


class L1Engine:
    """Compiled L1 regex rule engine. Scans text and returns matches."""

    def __init__(self, rules_path: str | None = None):
        raw_rules = load_builtin_rules()
        if rules_path:
            raw_rules = raw_rules + load_rules(rules_path)

        self._rules: list[tuple[CompiledRule, object]] = []
        self._engine_name: str = ""
        self._degraded: bool = False
        
        self._rules, self._engine_name, self._degraded = compile_rules(raw_rules)
        
        log.info("L1 engine: %s — %d rules loaded%s",
                 self._engine_name, len(self._rules),
                 " (degraded)" if self._degraded else "")

    @property
    def engine_name(self) -> str:
        return self._engine_name

    @property
    def degraded(self) -> bool:
        return self._degraded

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def scan(self, text: str) -> L1Result:
        """Scan canonicalized text and return all rule matches as Spans."""
        matches: list[Span] = []
        max_severity = 0.0
        timed_out_rules: list[str] = []

        for rule, compiled in self._rules:
            try:
                if self._degraded:
                    found = compiled.finditer(text, timeout=REGEX_TIMEOUT_SECONDS)
                else:
                    found = compiled.finditer(text)

                for m in found:
                    span = Span(
                        start=m.start(),
                        end=m.end(),
                        text=text[m.start():m.end()],
                        risk_score=rule.severity,
                        reason=f"L1: matched {rule.id} ({rule.category})",
                        matched_rules=[rule.id],
                    )
                    matches.append(span)
                    if rule.severity > max_severity:
                        max_severity = rule.severity
            except TimeoutError:
                timed_out_rules.append(rule.id)
                log.warning(
                    "L1 rule %s timed out after %dms with regex fallback",
                    rule.id,
                    int(REGEX_TIMEOUT_SECONDS * 1000),
                )

        return L1Result(
            matches=matches,
            max_severity=max_severity,
            engine=self._engine_name,
            engine_degraded=self._degraded,
            timed_out_rules=timed_out_rules,
        )
