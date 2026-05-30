# promptlint — Session Handoff

**Date:** 2026-05-29
**Status:** Architecture complete. Grill-me done (58 questions). Implementation plan written. Ready to build.

---

## What We Built (This Session)

promptlint is an open-source Python library that detects prompt injection attacks before user input reaches an LLM. v0 ships as a pip-installable library + FastAPI middleware. Target: 2 weeks.

### Artifacts Produced

| Artifact | Location | Source |
|----------|----------|--------|
| Architecture quality gate (initial) | `C:\Users\Caspe\LangChain\AIMentor-fresh\docs\collab\v3_docs\ARCHITECTURE_QUALITY_GATE.md` | Codex review of AI Mentor v3.0 |
| Architecture critique | `Obsidian/.../Projects/promptLint/Geminiprompt_firewall_architectural_critique.md` | Gemini |
| Architecture review | `Obsidian/.../Projects/promptLint/GPTprompt_firewall_architecture_review.md` | GPT-5.5 |
| L1 regex rules (7 of 20) | `Obsidian/.../Projects/promptLint/gemini-answer-1780103558738.md` | Gemini (truncated) |
| 25 hard negatives + policy engine | `Obsidian/.../Projects/promptLint/GPTprompt_firewall_hard_negatives_policy_escalation.md` | GPT-5.5 |
| Remaining 13 L1 rules | Grill-me session (Q&A between user and Codex, relayed) | User-designed |
| Revised architecture PRD | `Obsidian/.../Projects/promptLint/promptlint-v0-architecture.md` | Us (post-model review) |
| Master build spec | `Obsidian/.../Projects/promptLint/promptlint-master-spec.md` | Us (integrated) |
| Implementation plan | `C:\Users\Caspe\promptlint\IMPLEMENTATION_PLAN.md` | Us (post grill-me) |
| Codex handoff | `C:\Users\Caspe\promptlint\CodexPLAN.md` | Codex (session handoff) |
| AI News Digest | `Obsidian/.../AI News/AI News Digest - 2026-05-29.md` | Us |
| AI News Weekly Review | `Obsidian/.../AI News/AI News Weekly Review - 2026-05-29.md` | Us |
| v3.0 Architecture diagram | `C:\Users\Caspe\LangChain\AIMentor-fresh\docs\architecture\v3_architecture_diagram.html` | Us |
| AI Mentor architecture gate fixes | AI Mentor staging branch (`b39c1b20`) | Us |

### Other Work This Session
- Resolved AI Mentor v3.0 architecture quality gate (F-01, F-02, F-04 fixed; F-03 deferred; F-05 done by Codex)
- Shadow logger production guard added (`SHADOW_MODE_ALLOW_IN_PRODUCTION`)
- T-053 signoff doc reconciled
- T-063 cost regression waived
- Daily AI news digest + weekly review written to vault
- In-depth AutoTTS article summary
- Fixed memory: Caspe is CS student (not ME), graduating August 18, 2026

---

## Architecture Decisions (Locked)

All 58 grill-me questions resolved. Key decisions:

| Domain | Decision |
|--------|----------|
| v0 scope | Python core library + FastAPI middleware. TS deferred to v0.1. |
| Architecture | L0 → L1 → L2 → L4. L3 deferred. |
| L1 engine | google-re2 preferred. Fallback: re2 → regex with 50ms timeout. Degraded state logged at init. |
| L2 scoring | 6 signals, fixed weighted sum. Source-agnostic text analysis only. Severity floor = matched_rule.severity × 0.6. Quoting mitigation capped at 0.30. |
| L4 policy | 8 decision levels. 4 risk bands (0.30/0.60/0.80). Context from source + tools + quoted + task. Unknown tools default read_only, warn once. |
| L0 canonicalization | NFKD normalize + URL/HTML decode + strip zero-width + strip ANSI + detect bidi. Offset map translates canonical positions back to original. |
| Modes | monitor (default), block, paranoid. Mode is post-filter on L4 decision. |
| Middleware | Raw ASGI. JSON only. 100KB default max. Never mutates body. Scans explicit paths via dot + [*] syntax. Blocks only BLOCK/ESCALATE. |
| Rules format | YAML with 5 required fields (id, pattern, category, severity, description). Inline flags only. Extend by default. Collisions error at init. |
| Types | dataclasses + enums. No Pydantic at runtime. Pydantic for build-time YAML validation only. |
| CLI | String + stdin. Monitor default. Exit codes 0/1/2 (mode-filtered). --format human/json. |
| Hard negatives | Must NOT return BLOCK, ESCALATE, or REQUIRE_USER_CONFIRMATION. ALLOW/ALLOW_WITH_WARNING/ALLOW_AS_QUOTED_DATA pass. |
| REDACT_SPANS | Redacts annotation ranges. L0 annotations alone can drive decisions. |
| ALLOW_AS_QUOTED_DATA | Flagged spans become markdown blockquotes in result.text.safe. Surrounding text unchanged. |
| Multi-field | Aggregate = worst decision across fields. Per-field detail in result.fields. |
| User task mitigation | ~6 heuristic patterns (no LLM call). |

---

## What Still Needs Grilling

Only operational details remain (none block implementation):

- PyPI release checklist and version numbering convention
- CI matrix (Python 3.10/3.11/3.12 × Windows/Linux/macOS)
- Benchmark harness reporting format for README
- Error strategy for user-facing error messages
- Log level conventions (DEBUG vs INFO boundaries)

---

## Next Session: Implementation

**Repo:** `C:\Users\Caspe\promptlint`
**Plan:** `IMPLEMENTATION_PLAN.md` (15 tasks, 5 phases)
**Start at:** Phase 1, Task 1 — project scaffold

### Build Order Summary

```
Phase 1 (Foundation):
  Task 1: pyproject.toml + __init__.py + package scaffold
  Task 2: Public types (dataclasses + enums)
  Task 3: rules.yaml (20 rules)
  Task 4: L1 regex engine (re2/regex fallback)

Phase 2 (Tests):
  Task 5: 20 attack test cases
  Task 6: 25 hard negative test cases

Phase 3 (Pipeline):
  Task 7: L0 canonicalization
  Task 8: L2 signals + scorer
  Task 9: L4 policy engine
  Task 10: Firewall facade

Phase 4 (Integration):
  Task 11: FastAPI middleware
  Task 12: CLI
  Task 13: Structured logging
  Task 14: README + docs

Phase 5 (Gate):
  Task 15: Full pipeline benchmark harness
```

### Recommended Approach

Use `subagent-driven-development` skill — fresh `delegate_task` per task with full context. Two-stage review: spec compliance then code quality. TDD enforced (tests before code in every task).

### Skills to Load
- `writing-plans` (plan is written, load for context)
- `tdd-pocock` or `test-driven-development` (red-green-refactor)
- `subagent-driven-development` (task delegation)
- `requesting-code-review` (pre-commit quality gates)

---

## Vault References

All promptlint research and design docs:
```
C:\Users\Caspe\Obsidian\July'sBrain\0 - Hermes Memory\Projects\promptLint\
  ├── promptlint-v0-architecture.md          (revised architecture)
  ├── promptlint-master-spec.md              (integrated build spec)
  ├── GPTprompt_firewall_architecture_review.md
  ├── GPTprompt_firewall_hard_negatives_policy_escalation.md
  ├── Geminiprompt_firewall_architectural_critique.md
  └── gemini-answer-1780103558738.md         (L1 rules from Gemini)
```
