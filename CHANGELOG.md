# Changelog

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
