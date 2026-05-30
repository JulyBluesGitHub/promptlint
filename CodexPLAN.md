# Create Promptlint Grill Handoff

## Summary
Create `handoff/2026-05-29-grill-rest-of-session.md` in the promptlint repo. The repo currently has only `README.md`; the `handoff/` folder does not exist yet, so create it first.

## File Content
The handoff should capture the completed grilling decisions from Q1-Q58 and tee up the remaining grilling branches.

Use this structure:

- `Purpose`: continuation note for future grill-me sessions on promptlint v0.
- `Current State`: repo is essentially blank; no implementation exists yet.
- `Decisions Locked`: include the core decisions already settled:
  - v0 = Python library + thin FastAPI middleware; TS deferred.
  - monitor default everywhere.
  - FastAPI middleware scans explicit JSON paths, JSON only, 100KB default max, raw ASGI, never mutates request bodies.
  - public types use dataclasses/enums.
  - built-in + custom rules use runtime YAML, extend-only in v0, duplicate rule IDs fail startup.
  - L0 emits annotations, L1 emits spans, L2 scores text only, L4 owns source/tools/context decisions.
  - L1 runs on canonicalized text and maps spans back to original Python `str` offsets.
  - RE2 preferred; fallback chain is `google-re2` → `re2` → `regex` with timeout, with degraded diagnostics.
  - CLI supports string + stdin, monitor default, exits based on mode-filtered decision.
  - hard negatives allow only `ALLOW`, `ALLOW_WITH_WARNING`, `ALLOW_AS_QUOTED_DATA`.
  - unknown tools default to read-only, warn once per tool.
- `Open Grilling Work`: cover next session topics:
  - Final L2 scoring formula, severity floor, mitigation caps, and fixture thresholds.
  - Exact L4 decision table across risk band, source, tool tier, quoting, and task explanation.
  - Tool tier taxonomy and built-in name mapping.
  - L3 stub protocol and mock classifier behavior.
  - Package layout, extras, dependency groups, pyproject metadata.
  - Test fixture schema for 20 positives, 25 hard negatives, 5 end-to-end scenarios.
  - Benchmark harness details and README reporting.
  - FastAPI middleware response shape for BLOCK/ESCALATE.
  - CLI output format and serialization shape.
  - Release checklist for PyPI, CI matrix, docs, and issue-response workflow.
- `Suggested Skills`:
  - `grill-me`: continue decision-tree interrogation one question at a time.
  - `handoff`: update this file after each grilling session.
  - `tdd`: use when implementation starts so the fixture gates drive development.

## Verification
After creating the file, verify:
- `handoff/` exists.
- The Markdown file exists.
- It contains sections for locked decisions and open grilling work.
- No secrets, credentials, or private personal data are included.

## Assumptions
The handoff should live in this repo under `handoff/`, because the user explicitly asked for that folder, even though the generic handoff skill defaults to another notes directory.
