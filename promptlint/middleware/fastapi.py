"""FastAPI middleware for promptlint.

Raw ASGI middleware that:
  - Captures request body and JSON-parses it
  - Scans specified fields (dot-notation like "messages.*.content")
  - Attaches ScanResult to request.state.promptlint_result
  - Blocks (403) only on BLOCK/ESCALATE_TO_HUMAN decisions
  - Never mutates the request body
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from promptlint.firewall import Firewall
from promptlint.types import DECISION_SEVERITY, AppContext, Decision, ScanResult

log = logging.getLogger(__name__)

DEFAULT_MAX_BODY_SIZE = 100 * 1024  # 100 KB
DEFAULT_SCAN_FIELDS = ["messages.*.content", "prompt", "input", "text"]
DEFAULT_ROLE_SOURCES = {
    "user": "user_direct",
    "tool": "tool_output",
    "assistant": "model_output",
    "system": "system_instruction",
    "developer": "system_instruction",
}


class PromptlintMiddleware:
    """ASGI middleware that scans request bodies for prompt injection.

    Usage:
        from fastapi import FastAPI
        from promptlint.middleware.fastapi import PromptlintMiddleware

        app = FastAPI()
        app.add_middleware(
            PromptlintMiddleware,
            firewall=Firewall(mode="block"),
            scan_fields=["messages.*.content", "prompt"],
        )
    """

    def __init__(
        self,
        app: Any,
        firewall: Firewall | None = None,
        scan_fields: list[str] | None = None,
        max_body_size: int = DEFAULT_MAX_BODY_SIZE,
        on_scan: Callable[[ScanResult], None] | None = None,
        source: str = "user_direct",
        app_context: AppContext | None = None,
        field_sources: dict[str, str] | None = None,
        role_sources: dict[str, str] | None = None,
        app_context_factory: Callable[[dict, dict], Any] | None = None,
        unscannable_action: str = "allow",
    ):
        if unscannable_action not in {"allow", "block"}:
            raise ValueError("unscannable_action must be 'allow' or 'block'")
        self.app = app
        self.firewall = firewall or Firewall()
        self.scan_fields = scan_fields or DEFAULT_SCAN_FIELDS
        self.max_body_size = max_body_size
        self.on_scan = on_scan
        self.source = source
        self.app_context = app_context
        self.field_sources = field_sources or {}
        self.role_sources = {**DEFAULT_ROLE_SOURCES, **(role_sources or {})}
        self.app_context_factory = app_context_factory
        self.unscannable_action = unscannable_action

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Read body, stopping early once the cap is exceeded in fail-closed
        # mode so an oversized request cannot force unbounded buffering.
        body_chunks: list[bytes] = []
        total_size = 0
        more_body = True
        over_limit = False

        while more_body:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                body_chunks.append(chunk)
                total_size += len(chunk)
                more_body = message.get("more_body", False)
                if total_size > self.max_body_size:
                    over_limit = True
                    if self.unscannable_action == "block":
                        break

        body_bytes = b"".join(body_chunks)

        # Skip empty bodies
        if not body_bytes:
            await self._replay_request(scope, receive, send, body_bytes, None)
            return

        # Handle oversized bodies
        if over_limit:
            log.warning(
                "Body size %d exceeds max %d — body is unscannable", total_size, self.max_body_size
            )
            if self.unscannable_action == "block":
                await self._send_unscannable(send, "body_too_large", status=413)
                return
            scope.setdefault("state", {})["promptlint_skip_reason"] = "body_too_large"
            await self._replay_request(scope, receive, send, body_bytes, None)
            return

        # Parse JSON and scan. Unscannable bodies follow the configured policy.
        try:
            parsed_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            if self.unscannable_action == "block":
                await self._send_unscannable(send, "malformed_json")
                return
            scope.setdefault("state", {})["promptlint_skip_reason"] = "malformed_json"
            await self._replay_request(scope, receive, send, body_bytes, None)
            return

        if not isinstance(parsed_body, dict):
            if self.unscannable_action == "block":
                await self._send_unscannable(send, "non_object_json")
                return
            scope.setdefault("state", {})["promptlint_skip_reason"] = "non_object_json"
            await self._replay_request(scope, receive, send, body_bytes, None)
            return

        result = await self._scan_body(body_bytes, scope=scope)
        if result is None:
            if self.unscannable_action == "block":
                await self._send_unscannable(send, "no_scannable_fields")
                return
            scope.setdefault("state", {})["promptlint_skip_reason"] = "no_scannable_fields"

        # Callback
        if self.on_scan and result:
            callback_result = self.on_scan(result)
            if inspect.isawaitable(callback_result):
                await callback_result

        # Block on BLOCK or ESCALATE
        if result and result.decision in (Decision.BLOCK, Decision.ESCALATE_TO_HUMAN):
            await self._send_blocked(send, result)
            return

        # Replay request body for the app
        await self._replay_request(scope, receive, send, body_bytes, result)

    async def _scan_body(
        self,
        body_bytes: bytes,
        scope: dict | None = None,
    ) -> ScanResult | None:
        """Parse body JSON and scan configured fields."""
        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError:
            return None

        if not isinstance(body, dict):
            return None

        # Collect values from configured scan fields
        field_values: dict[str, tuple[str, str]] = {}
        for field_pattern in self.scan_fields:
            values = self._extract_field(body, field_pattern)
            for path, value in values.items():
                if isinstance(value, str) and value.strip():
                    field_values[path] = (value, field_pattern)

        if not field_values:
            return None

        scan_context = self.app_context
        if self.app_context_factory:
            produced = self.app_context_factory(scope or {}, body)
            scan_context = await produced if inspect.isawaitable(produced) else produced
            if not isinstance(scan_context, AppContext):
                raise TypeError("app_context_factory must return AppContext")

        # Scan each field
        field_results: dict[str, ScanResult] = {}
        for path, (value, field_pattern) in field_values.items():
            result = self.firewall.scan(
                value,
                source=self._source_for_field(path, field_pattern, body),
                app_context=scan_context,
            )
            field_results[path] = result

        # Aggregate: worst decision wins
        from promptlint.l4 import aggregate_decisions

        decisions = [r.decision for r in field_results.values()]
        worst_decision = aggregate_decisions(decisions)
        worst_l4_decision = aggregate_decisions([r.l4_decision for r in field_results.values()])

        # Use the worst decision as the aggregate; risk score breaks ties.
        worst_field = max(
            field_results.values(),
            key=lambda r: (DECISION_SEVERITY.get(r.decision, 0), r.risk_score),
        )

        aggregate = replace(
            worst_field,
            decision=worst_decision,
            l4_decision=worst_l4_decision,
            risk_score=max(r.risk_score for r in field_results.values()),
            fields=field_results,
            aggregate=None,
        )
        for field_result in field_results.values():
            field_result.aggregate = aggregate

        return aggregate

    def _source_for_field(
        self,
        path: str,
        field_pattern: str,
        body: dict | None = None,
    ) -> str:
        """Return source override for a field pattern or extracted path."""
        if field_pattern in self.field_sources:
            return self.field_sources[field_pattern]
        if path in self.field_sources:
            return self.field_sources[path]
        if body is not None:
            match = re.fullmatch(r"messages\[(\d+)\]\.content", path)
            if match:
                messages = body.get("messages")
                index = int(match.group(1))
                if isinstance(messages, list) and index < len(messages):
                    message = messages[index]
                    if isinstance(message, dict):
                        role = message.get("role")
                        if isinstance(role, str) and role in self.role_sources:
                            return self.role_sources[role]
        return self.source

    def _extract_field(self, obj: Any, pattern: str, prefix: str = "") -> dict[str, Any]:
        """Extract values from a nested dict using dot-notation with wildcards.

        Examples:
            "messages.*.content" — all content fields in a messages array
            "prompt" — top-level prompt key
        """
        results: dict[str, Any] = {}
        parts = pattern.split(".")
        self._extract_recursive(obj, parts, prefix, results)
        return results

    def _extract_recursive(
        self,
        obj: Any,
        parts: list[str],
        current_path: str,
        results: dict[str, Any],
    ) -> None:
        if not parts:
            return

        part = parts[0]
        rest = parts[1:]

        if part == "*":
            if isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                    self._extract_recursive(item, rest, new_path, results)
        elif isinstance(obj, dict) and part in obj:
            value = obj[part]
            new_path = f"{current_path}.{part}" if current_path else part
            if not rest:
                results[new_path] = value
            else:
                self._extract_recursive(value, rest, new_path, results)

    async def _replay_request(
        self,
        scope: dict,
        receive: Callable,
        send: Callable,
        body: bytes,
        result: ScanResult | None,
    ) -> None:
        """Replay the request body to the downstream app."""
        body_sent = False

        async def _receive() -> dict:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }
            return await receive()

        # Inject result into request state via scope
        if result and "state" not in scope:
            scope["state"] = {}
        if result:
            scope["state"]["promptlint_result"] = result

        await self.app(scope, _receive, send)

    async def _send_blocked(self, send: Callable, result: ScanResult) -> None:
        """Send a 403 response for blocked requests."""
        body = json.dumps(
            {
                "detail": "Prompt injection detected",
                "decision": result.decision.value,
                "risk_score": result.risk_score,
            }
        ).encode("utf-8")

        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )

    async def _send_unscannable(
        self,
        send: Callable,
        reason: str,
        *,
        status: int = 400,
    ) -> None:
        body = json.dumps(
            {
                "detail": "Request body could not be scanned",
                "reason": reason,
            }
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
