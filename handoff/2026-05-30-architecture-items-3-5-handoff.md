# promptlint Handoff: Architecture Items 3-5

**Date:** 2026-05-30
**Repo:** `C:\Users\Caspe\promptlint`
**Focus:** Implement remaining architecture improvements from the second `improve-codebase-architecture` pass.

## Purpose

Continue hardening promptlint after the latest architecture review. Items #1 and #2 from the priority list were implemented in the current working tree:

- Real regex fallback timeout enforcement in L1.
- Custom rules now extend built-ins instead of replacing them.

This handoff covers the implementation plan for remaining items #3, #4, and #5:

1. Span translation ownership.
2. Middleware field context.
3. Policy context validation.

## Current State

The working tree is intentionally dirty with completed fixes and tests from the current session:

- `promptlint/l1/compiler.py`
- `promptlint/l1/engine.py`
- `promptlint/types.py`
- `tests/test_l1_engine.py`
- Prior fixes are also present in `firewall.py`, `l0/canonicalize.py`, `cli.py`, `middleware/fastapi.py`, and related tests.

Latest verification:

- `python -m pytest`
- Result: `177 passed in 0.63s`

No `CONTEXT.md`, `CONTEXT-MAP.md`, or `docs/adr/` exists in this repo.

## Work Completed

Relevant completed changes before this handoff:

- Safe-text redaction/quoting now translates normalized L1 spans back to original text before rewriting.
- L0 URL and HTML decoding preserve better original-position boundaries.
- CLI `--tools` now passes `AppContext(available_tools=...)`.
- Middleware aggregation now selects by worst decision severity, then score, and populates `aggregate`.
- L1 fallback now enforces `REGEX_TIMEOUT_SECONDS` at `finditer(..., timeout=...)`.
- `L1Result.timed_out_rules` reports timed-out fallback rules.
- `L1Engine(rules_path=...)` loads built-ins first, then custom rules; duplicate IDs still fail.

## Next Session Focus

Implement items #3, #4, and #5 in this order unless the user changes priority:

1. Span translation ownership.
2. Middleware field context.
3. Policy context validation.

Each item should be implemented with focused contract tests before or alongside code changes.

## Open Work

### 3. Span Translation Ownership

Goal: move offset-map semantics out of `Firewall` and behind L0.

Current friction:

- `Firewall._span_ranges_in_original`, `_original_boundary`, and `_merge_ranges` understand `CanonicalizationResult.offset_map`.
- That makes the facade depend on an L0 implementation detail.
- L0 should own the contract: given spans in normalized text, return original text ranges or projected spans.

Recommended implementation plan:

1. Add a small public method or helper owned by L0. Preferred shape:
   - `CanonicalizationResult.translate_spans(spans: list[Span]) -> list[Span]`
   - or `project_spans_to_original(result: CanonicalizationResult, spans: list[Span]) -> list[Span]`
2. Preserve original matched metadata:
   - `risk_score`
   - `reason`
   - `matched_rules`
   - `source`
3. Decide what translated `Span.text` means:
   - recommended: original text slice for the projected range.
   - document that input spans are normalized-coordinate spans.
4. Move range merging into L0 or a small text-projection helper near L0.
5. Update `Firewall._produce_safe_text` to accept already-translated spans or simple original ranges.
6. Delete `_span_ranges_in_original` and `_original_boundary` from `Firewall`.
7. Keep existing regression test:
   - `tests/test_firewall.py::test_firewall_redacts_original_text_after_l0_normalization`
8. Add direct L0 tests:
   - zero-width projection
   - URL-decoded projection
   - overlapping normalized spans merge/project correctly

Files likely touched:

- `promptlint/types.py`
- `promptlint/l0/canonicalize.py`
- `promptlint/firewall.py`
- `tests/test_l0.py`
- `tests/test_firewall.py`

Risk:

- Be careful with encoded sequences where multiple original chars map to one normalized char.
- Keep existing public dataclass fields backward compatible.

### 4. Middleware Field Context

Goal: let FastAPI middleware pass source/tools/task context into `Firewall.scan` per request or per field.

Current friction:

- `PromptlintMiddleware._scan_body` calls `self.firewall.scan(value)` with default `source="user_direct"` and no `AppContext`.
- This is inaccurate for RAG endpoints, tool outputs, logs, emails, or apps with known available tools.
- Direct API users get better context-aware policy decisions than middleware users.

Recommended implementation plan:

1. Add optional middleware constructor parameters:
   - `source: str = "user_direct"` as default source for all fields.
   - `app_context: AppContext | None = None` as default context for all fields.
   - `field_sources: dict[str, str] | None = None` for exact extracted-path or configured-pattern source overrides.
   - Optional later: `field_contexts: dict[str, AppContext] | None = None`, but start smaller if possible.
2. Decide matching semantics for `field_sources`:
   - simplest: keys match extracted paths such as `messages[0].content` or top-level `prompt`.
   - more ergonomic: keys match configured field patterns such as `messages.*.content`.
   - recommended first pass: support configured field-pattern mapping because users know those names at construction time.
3. Preserve backward compatibility:
   - no new args required.
   - default behavior remains user_direct/no tools.
4. Internally collect not just `path -> value`, but `path -> (value, source, app_context)`.
5. Pass context through:
   - `self.firewall.scan(value, source=field_source, app_context=field_context)`
6. Add tests:
   - default middleware still scans as before.
   - configured source changes the resulting decision for retrieved documents.
   - configured app context tools affect policy decision.
   - per-field source beats default source.
7. Update README FastAPI middleware docs with one contextual example.

Files likely touched:

- `promptlint/middleware/fastapi.py`
- `promptlint/types.py` only if a new context type is needed; avoid if possible.
- `tests/test_middleware.py`
- `README.md`

Risk:

- Do not make middleware configuration too clever. Keep the first interface small and explicit.
- Existing tests use fake firewalls with `scan(value)` only. Update fakes to accept `source` and `app_context` if the call signature changes.

### 5. Policy Context Validation

Goal: prevent silent policy misconfiguration and reduce mutable module state.

Current friction:

- Tool tiers are plain strings.
- `custom_tiers={"tool": "eleveated"}` silently falls through in ranking and effectively behaves like read-only.
- `_unknown_tool_warnings` is mutable module-level state, awkward for tests and long-lived processes.

Recommended implementation plan:

1. Introduce validation for tier strings before considering an enum migration:
   - allowed values: `read_only`, `network`, `write`, `elevated`.
   - invalid custom tier values should raise `ValueError`.
2. Add helper:
   - `validate_tool_tiers(custom_tiers: dict[str, str]) -> dict[str, str]`
   - or validate inside `classify_tools`.
3. Decide what to do with `TOOL_TIER_UNKNOWN`:
   - it is currently unused as a returned tier.
   - either remove it or leave it only if an ADR-level reason exists. There is no ADR currently.
4. Reduce global warning state:
   - option A: keep warn-once but move warning registry into a `ToolClassifier` object.
   - option B: remove warn-once behavior and always log unknown tools at DEBUG/WARNING.
   - recommended: create a small `ToolClassifier` with `custom_tiers` and `_unknown_tool_warnings` instance state, then have `classify_tools(...)` remain a backward-compatible wrapper.
5. Update `Firewall` to instantiate/use classifier if that does not overcomplicate construction.
6. Add tests:
   - invalid custom tier raises.
   - unknown tools still default read-only.
   - warning state does not leak between classifier instances.
   - existing `classify_tools` API remains compatible.

Files likely touched:

- `promptlint/l4/policy.py`
- `promptlint/firewall.py`
- `tests/test_l4.py`
- possibly `tests/test_firewall.py`

Risk:

- Raising on invalid custom tier is a behavior change, but it is safer than silent downgrade.
- If adding `ToolClassifier`, keep the old function so public imports from `promptlint.l4` do not break.

## Key Decisions And Constraints

- Preserve dataclass/enums runtime model. No Pydantic runtime dependency.
- Preserve public `Firewall.scan(text, source="user_direct", app_context=None)` signature unless there is a clear reason to change it.
- Keep package backward compatibility where possible.
- Keep tests focused on public contracts, not just score ranges.
- Do not commit unless the user explicitly asks.

## Artifacts To Read

- `README.md`
- `promptlint/types.py`
- `promptlint/firewall.py`
- `promptlint/l0/canonicalize.py`
- `promptlint/l4/policy.py`
- `promptlint/middleware/fastapi.py`
- `tests/test_l0.py`
- `tests/test_firewall.py`
- `tests/test_l4.py`
- `tests/test_middleware.py`
- `tests/test_l1_engine.py`

## Suggested Skills

- `improve-codebase-architecture`: use if the next agent wants to re-check module depth after implementing items 3-5.
- `tdd`: useful for writing contract tests first for each item.
- `handoff`: use again after implementation if the work spans another session.

## Verification

Before handing back:

1. Run `python -m pytest`.
2. Confirm all existing public behavior still passes.
3. Check `git diff` for accidental unrelated changes.
4. If README changes, verify examples match the actual middleware constructor.

## Risks Or Unknowns

- The best middleware field-source mapping interface is still a product decision. Start with a small backward-compatible API.
- Span projection should be owned by L0, but choose whether it returns `Span` objects or primitive ranges before editing.
- Policy context validation can be done incrementally; full enum migration is probably unnecessary for the first pass.
