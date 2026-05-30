"""CLI for promptlint — prompt injection detection from the command line.

Usage:
    promptlint check "text to scan"
    echo "text to scan" | promptlint check
    promptlint check --mode block --source tool_output "text"

Exit codes:
    0 — ALLOW / ALLOW_WITH_WARNING (safe)
    1 — ALLOW_AS_QUOTED_DATA / DISABLE_TOOL_CALLS / REDACT_SPANS (caution)
    2 — REQUIRE_USER_CONFIRMATION / BLOCK / ESCALATE_TO_HUMAN (block)
"""

from __future__ import annotations

import argparse
import json
import sys

from promptlint.firewall import Firewall
from promptlint.types import AppContext, Decision


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="promptlint",
        description="Detect prompt injection attacks in text.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Scan text for prompt injection")
    check.add_argument(
        "text",
        nargs="?",
        help="Text to scan (reads from stdin if omitted)",
    )
    check.add_argument(
        "--source",
        default="user_direct",
        choices=["user_direct", "retrieved_document", "tool_output", "webpage", "email", "log"],
        help="Source of the text (default: user_direct)",
    )
    check.add_argument(
        "--tools",
        default="",
        help="Comma-separated list of available tools for L4 policy",
    )
    check.add_argument(
        "--mode",
        default="monitor",
        choices=["monitor", "block", "paranoid"],
        help="Operating mode (default: monitor)",
    )
    check.add_argument(
        "--format",
        default="human",
        choices=["human", "json"],
        help="Output format (default: human)",
    )
    check.add_argument(
        "--rules",
        default=None,
        help="Path to custom rules.yaml file",
    )

    args = parser.parse_args()

    if args.command == "check":
        _cmd_check(args)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_check(args: argparse.Namespace) -> None:
    text = args.text
    if text is None:
        # Read from stdin
        text = sys.stdin.read().strip()
        if not text:
            print("Error: no input provided (empty stdin)", file=sys.stderr)
            sys.exit(1)

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]

    fw = Firewall(mode=args.mode, rules_path=args.rules)
    result = fw.scan(text, source=args.source, app_context=AppContext(available_tools=tools))

    if args.format == "json":
        _output_json(result)
    else:
        _output_human(result)

    # Exit code based on decision
    if result.decision in (Decision.ALLOW, Decision.ALLOW_WITH_WARNING):
        sys.exit(0)
    elif result.decision in (
        Decision.ALLOW_AS_QUOTED_DATA,
        Decision.DISABLE_TOOL_CALLS,
        Decision.REDACT_SPANS,
    ):
        sys.exit(1)
    else:
        # REQUIRE_USER_CONFIRMATION, BLOCK, ESCALATE_TO_HUMAN
        sys.exit(2)


def _output_human(result) -> None:
    """Human-readable output."""
    decision = result.decision.value
    score = result.risk_score
    mode = result.mode

    # Color-coded or plain output
    if decision in ("BLOCK", "ESCALATE_TO_HUMAN"):
        status = f"[CRITICAL] {decision}"
    elif decision in ("ALLOW", "ALLOW_WITH_WARNING"):
        status = f"[OK] {decision}"
    else:
        status = f"[CAUTION] {decision}"

    print(f"{status}")
    print(f"  Score: {score:.3f} (mode: {mode})")

    if result.spans:
        print(f"  Matches: {len(result.spans)}")
        for span in result.spans[:5]:  # Show first 5
            print(f"    - {span.reason} | severity={span.risk_score:.2f}")
        if len(result.spans) > 5:
            print(f"    ... and {len(result.spans) - 5} more")

    if result.l1:
        print(f"  Engine: {result.l1.engine}")

    if result.l4_decision != result.decision:
        print(f"  Raw L4 decision: {result.l4_decision.value} (filtered by mode '{mode}')")


def _output_json(result) -> None:
    """JSON output."""
    output = {
        "decision": result.decision.value,
        "l4_decision": result.l4_decision.value,
        "risk_score": result.risk_score,
        "mode": result.mode,
        "spans": [
            {
                "start": s.start,
                "end": s.end,
                "risk_score": s.risk_score,
                "reason": s.reason,
                "matched_rules": s.matched_rules,
            }
            for s in result.spans
        ],
        "diagnostics": result.diagnostics,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
