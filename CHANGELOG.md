# Changelog

## [0.5.1] - 2026-09-05

### Changed
- Documentation only. Unslop the README, CHANGELOG, and CONTEXT; add a
  Limitations section to the README; correct the CONTEXT L3 description; switch
  the default branch from `master` to `main`.

## [0.5.0] - 2026-09-05

### Changed
- Replaced the logistic-regression ML head with a fine-tuned MiniLM classifier
  (`ft_minilm.onnx`) that attends over the message and its system prompt, so it
  catches indirect attacks like riddles, word games, and acrostics that only read as
  malicious given the surrounding context. Torch-free at inference (onnxruntime).
- Added `Firewall.scan(..., system_prompt=...)` to pass surrounding context to
  the ML layer; `PromptInjectionClassifier.score(text, system_prompt=...)` takes
  the same. The ML layer remains escalation-only and threshold-configurable.
- Retrained on game-style injection data (Gandalf-RCT, with the real secret in
  the prompt) plus xTRam1/Mosscap/gandalf-ignore and multilingual benign
  (Alpaca + OpenAssistant), fixing two prior shortcuts: "non-English == attack"
  and "specific secret in prompt == attack".

### Results (held-out / external)
- Gandalf-RCT (held-out): ~95% recall across five secret phrasings at threshold
  0.8, vs ~83% for the previous LR head.
- External Lakera Mosscap (2000): 93% recall (previous LR: 85%).
- Benign FPR ~1% (Alpaca); indirect attacks like "Help me solve this riddle"
  now score ~1.0 with context vs ~0.3 without.

## [0.4.0] - 2026-09-05

### Changed
- Retrained the ML layer on game-style injection data (Lakera Mosscap) in
  addition to xTRam1 + Gandalf + Alpaca. On genuinely external Lakera datasets
  (none seen in training) recall rose from ~49% to ~93% at the 0.5 threshold,
  including on Gandalf-RCT, which was never in training, confirming the model
  learned transferable attack semantics rather than memorizing examples.
- Raised the default `ml_threshold` from 0.5 to 0.8 to keep the benign-warning
  rate low (85% recall / 1.5% warning rate, vs 93% / 5.2% at 0.5). The ML layer
  remains escalation-only and the threshold stays configurable per `Firewall`.

## [0.3.0] - 2026-09-05

### Added
- Optional ML layer (L3): a torch-free MiniLM + logistic-regression classifier
  (`promptlint.ml.PromptInjectionClassifier`) that catches paraphrased injections
  the regex rules miss. Escalation-only. It can promote a silent `ALLOW` to a
  warning but never weakens a deterministic decision. Requires the `[ml]` extra
  (`onnxruntime` + `tokenizers`) and model assets downloaded on first use from
  the GitHub release.

## [0.2.0] - 2026-09-05

### Security
- Removed implicit trust/demotion for retrieved documents, email, and logs
- Unknown tools now default to `write`; legacy behavior remains opt-in
- Critical findings can no longer be waived by task-explanation text
- Added explicit caller-owned `content_trust` policy input
- Recalibrated the severity floor so unquoted high-severity (0.95+) matches
  reach `BLOCK` in block mode. Previously capped at ~0.60 and never blocked
- Closed L0 evasions: strip NFKD combining marks, convert line/paragraph
  separators to spaces, and decode HTML numeric references without a semicolon
- Middleware: fixed an `http.disconnect` busy-loop (worker wedge), bounded body
  buffering in fail-closed mode, scan list-typed OpenAI/Anthropic `content`
  parts, and removed the 403 decision/score evasion oracle (now logged only)
- Made `REDACT_SPANS` also disable tools (previously inverted vs. its severity)
- `regex` fallback is now always installable (was missing on Linux/macOS py≥3.11)
- Recorded `source` provenance on `ScanResult` and surfaced `truncated` /
  `timed_out_rules` in diagnostics
- `content_trust="trusted"` no longer demotes critical (`BLOCK`/`ESCALATE`)
  findings. Trust mitigates warnings/restrictions, never a near-certain injection
- PL-023 now requires an external/attacker destination, eliminating false
  positives on ordinary tool use (e.g. "send a summary to my team")
- Added per-field `field_trust` so trusting one field (e.g. the system prompt)
  never implicitly trusts user/tool message fields in the same request
- The task-explanation waiver now requires the task to reference content that
  actually appears in the payload, and it never crosses out of the medium band
  (a bare "review this email" no longer waives an attacker-quoted injection)
- PL-021 widened to catch paraphrased destructive verbs (`rm`/`remove`/`drop`)
  and possessive/filler tokens (`your`, `then`, markdown emphasis)
- Middleware now offloads field scanning to a worker thread (so a single
  request cannot block the event loop) and caps the scan-field count
  (`max_fields`, default 200) with fail-closed handling
- PL-024 widened to catch query-value, path-segment, fragment, and `<img src>`
  exfiltration; it no longer flags legitimate presigned URLs (sensitive
  keywords must appear in a value/path position, not a parameter name)
- Strong bidi directional controls (U+202A to U+202E, U+2066 to U+2069) now become
  spaces in normalized text instead of surviving to break `\s` in L1 rules
- L0 annotation offsets are now uniformly canonical (stage-local) and documented
  as such on `Annotation` (previously `confusable`/`separator` mixed
  original-text offsets with the rest)
- Confusable skeletonization is now Latin-context-sensitive: Cyrillic/Greek
  lookalikes map to ASCII only when adjacent to a Latin letter, so legitimate
  Russian/Greek text is no longer mangled into mixed-script text and no longer
  accrues spurious `encoding_suspicion` (homoglyph attacks still resolve)
- Middleware now bounds body buffering in the default (`allow`) mode too:
  an oversized body is streamed through to the app instead of being fully
  buffered, so a client can no longer force unbounded allocation
- Expanded the regression corpus (16 → 24 cases) with L0-obfuscation attacks
  (bidi controls, combining marks, HTML entities without semicolons, path-segment
  exfiltration) and real-world/multilingual benign cases (ordinary tool use,
  Russian, Greek, presigned URLs), so the CI gate no longer certifies only the
  literal rule-authoring examples

### Added
- Typed `Finding`, `RiskDimension`, and `ActionConstraints` outputs
- Added PL-021 through PL-024 for destructive supply-chain injection, paraphrased role confusion, tool exfiltration, and markdown-image exfiltration
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
- CI tests Python 3.10 to 3.14 across Linux, Windows, and macOS

### Fixed
- Restored multilingual hard-negative fixtures that had been unintentionally transliterated
- Nested URL/HTML encodings now decode to a bounded fixed point
- Encoded confusable characters are normalized after decoding

### Migration notes
- Applications relying on unknown tools being classified `read_only` must pass `unknown_tool_tier="read_only"` explicitly.
- Source values no longer reduce risk. Use `AppContext(content_trust="trusted")` only after deterministic application-level origin/integrity checks.
- `task_explains` only mitigates quoted, non-critical content.

## [0.1.1] - 2026-05-30

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
- `CanonicalizationResult` is now a pure dataclass. Projection moved to `l0.projection`
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

## [0.1.0] - 2026-05-29

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
