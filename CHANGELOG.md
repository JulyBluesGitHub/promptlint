# Changelog

## [0.2.0] — 2026-09-04

### Security
- Removed implicit trust/demotion for retrieved documents, email, and logs
- Unknown tools now default to `write`; legacy behavior remains opt-in
- Critical findings can no longer be waived by task-explanation text
- Added explicit caller-owned `content_trust` policy input
- Added PL-021 through PL-024 for destructive supply-chain injection, paraphrased role confusion, tool exfiltration, and markdown-image exfiltration

### Added
- Typed `Finding`, `RiskDimension`, and `ActionConstraints` outputs
- Bounded iterative URL/HTML decoding and conservative Cyrillic/Greek confusable normalization
- Versioned evaluation corpus and `evaluate()` Python API
- `promptlint evaluate` CLI with precision, recall, false-positive rate, category recall, regression IDs, latency, and metric gates
- Role-aware FastAPI source mapping, async callbacks, and per-request context factories
- Configurable middleware fail-closed handling with typed skip reasons
- Python 3.13 and 3.14 test coverage
- Ruff, mypy, branch coverage, dependency audit, package smoke tests, Dependabot, and OIDC trusted publishing
- `SECURITY.md` and `CONTRIBUTING.md`

### Changed
- Package version is derived from installed distribution metadata
- Architecture documentation now positions promptlint as one deterministic defense-in-depth signal, not a complete security boundary
- CI tests Python 3.10–3.14 across Linux, Windows, and macOS

### Fixed
- Restored multilingual hard-negative fixtures that had been unintentionally transliterated
- Nested URL/HTML encodings now decode to a bounded fixed point
- Encoded confusable characters are normalized after decoding

### Migration notes
- Applications relying on unknown tools being classified `read_only` must pass `unknown_tool_tier="read_only"` explicitly.
- Source values no longer reduce risk. Use `AppContext(content_trust="trusted")` only after deterministic application-level origin/integrity checks.
- `task_explains` only mitigates quoted, non-critical content.

## [0.1.1] — 2026-05-30

### Added
- `--task` flag to CLI for user task mitigation testing
- Monitoring & data collection guide in CONTEXT.md
- Per-field source resolution in FastAPI middleware
- `ToolClassifier` with validation for custom tool tiers
- `timed_out_rules` tracking on L1Result when regex fallback times out
- Domain glossary in CONTEXT.md

### Changed
- **Breaking**: Firewall.scan() now raises `ValueError` for invalid source strings (was silent fallback)
- **Breaking**: L4 `decide()` now validates `tool_tier` against allowed values
- `CanonicalizationResult` is now a pure dataclass — projection moved to `l0.projection`
- L2 scorer no longer caps scores for task-explained content (L4 owns that decision)
- Custom rules now extend built-in rules instead of replacing them
- Middleware aggregation uses worst decision, not highest risk score

### Fixed
- 5 regex rules fixed from test feedback (PL-002, -003, -009, -011, -020)
- Span translation handles zero-width obfuscation correctly via offset_map
- `importlib.resources` deprecation: switched to `files()` API
- `promptlint.egg-info` removed from repo tracking

### Removed
- Internal dev artifacts from public repo (handoff files, implementation plans)

## [0.1.0] — 2026-05-29

### Added
- Initial release
- L0 canonicalization (NFKD, URL decode, zero-width strip, bidi detection)
- L1 regex engine with 20 rules (google-re2 preferred, regex fallback with 50ms timeout)
- L2 contextual scoring (6 heuristic signals)
- L4 policy engine (8 decisions, 3 modes, 4 risk bands)
- Firewall facade with `scan()` API
- FastAPI middleware (raw ASGI, JSON field scanning)
- CLI: `promptlint check` with exit codes 0/1/2
- Structured JSON-per-line logging
- 190 tests: 20 attack cases, 25 hard negatives, 5 policy scenarios
