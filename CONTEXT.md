# promptlint — Domain Context

This file defines the shared vocabulary and invariants for promptlint architecture, tests, and behavior.

## Product boundary

promptlint is a deterministic security signal, not a complete prompt-injection solution. It detects known structures and suspicious textual signals, then maps evidence plus application-owned context to enforceable constraints. Authorization, output validation, egress controls, isolation, and human approval remain the integrating application's responsibility.

## Architecture layers

### L0 — Canonicalization

Normalizes input without deciding risk. It produces:

- `normalized`: text scanned by L1/L2
- `offset_map`: normalized-to-original positions
- `annotations`: encoding/obfuscation observations
- `truncated`: the bounded decode pass budget was exhausted while content was still changing

Transforms include NFKD normalization, bounded iterative URL/HTML decoding, conservative cross-script confusable skeletonization, zero-width removal, ANSI removal, and bidi-control detection.

Invariant: every normalized match must project to a valid original range.

### L1 — Regex signatures

Runs 24 built-in google-re2-compatible signatures (or the timeout-protected `regex` fallback). It emits `Span` evidence with rule ID, category, severity, and normalized coordinates. L1 never modifies text or makes policy decisions.

### L2 — Contextual scoring

Combines seven source-agnostic textual signals:

1. maximum L1 severity
2. instruction density
3. destructive verbs
4. authority claims
5. encoding suspicion
6. quoted context
7. semantic shift

Task-explanation detection is reported as context evidence. The severity floor
is quoting-aware: unquoted high-severity matches can reach the critical BLOCK
band, while quoted matches keep a conservative floor so legitimate
debugging/educational quoting is warned or wrapped rather than hard-blocked.
L2 never assigns application trust and never makes policy decisions.

### L3 — Optional classifier seam

Reserved for future classifier adapters. No network or model dependency is shipped in the core package. Any future adapter must report evidence without becoming the sole authorization control.

### L4 — Policy

Combines risk score, explicit content trust, tool capability, quoting evidence, and operating mode. L4 owns all policy decisions.

Security invariants:

- provenance does not imply trust
- retrieved documents, tool output, web pages, email, logs, and model output are potentially attacker-controlled
- only `content_trust="trusted"` can reduce a decision, and it never reduces a critical (`BLOCK`/`ESCALATE`) finding
- explanatory task text cannot waive critical risk
- unknown tools default to `write`
- critical elevated-tool risk escalates to human review

## Core types

### Source

Where text originated:

- `user_direct`
- `retrieved_document`
- `tool_output`
- `webpage`
- `email`
- `log`
- `model_output`
- `system_instruction`

Source is provenance metadata, not a trust ranking.

### Content trust

`AppContext.content_trust` is `untrusted` by default. `trusted` is an application assertion that should only be set after deterministic origin/integrity checks outside the model. In the middleware, `field_trust` scopes that assertion per field, so marking the system prompt trusted does not also trust user/tool messages.

### Tool tier

- `read_only`
- `network`
- `write`
- `elevated`

The highest available capability governs policy. Unknown tool names default to `write` unless the caller explicitly chooses another fallback.

### Decision

Compatibility policy output, ordered for legacy aggregation:

`ALLOW` → `ALLOW_WITH_WARNING` → `ALLOW_AS_QUOTED_DATA` → `DISABLE_TOOL_CALLS` → `REDACT_SPANS` → `REQUIRE_USER_CONFIRMATION` → `BLOCK` → `ESCALATE_TO_HUMAN`

Do not infer that all decisions solve the same risk dimension; use `ActionConstraints` for enforcement.

### Finding

Typed detection evidence independent of enforcement:

- rule ID and category
- `RiskDimension`
- severity
- original text coordinates
- matched text and reason

Risk dimensions include instruction override, prompt extraction, data exfiltration, destructive action, obfuscation, privilege escalation, and memory manipulation.

### ActionConstraints

Orthogonal enforcement outputs:

- `allow_model_input`
- `allow_tools`
- `redact_spans`
- `require_confirmation`
- `require_human_review`

### Span

A suspicious range. L1 spans use normalized coordinates; public `ScanResult.spans` use original coordinates.

### Safe text

`ScanResult.text.safe` is derived from the compatibility decision: pass-through, quoted ranges, redacted ranges, `[BLOCKED]`, or `[ESCALATED]`.

### AppContext

Caller-owned security context:

- `available_tools`
- `user_task`
- `content_trust`

## Operating modes

- `monitor`: critical block/escalate decisions are reported as warnings; content is not rejected
- `block`: policy decisions pass through
- `paranoid`: allow/warning decisions are elevated

Mode filtering occurs after raw L4 policy. `ScanResult.l4_decision` is raw; `ScanResult.decision` is mode-filtered.

## FastAPI adapter

The middleware is a thin adapter around the scan facade. It supports:

- dot-path/wildcard JSON extraction
- role-aware message provenance
- explicit field-source overrides
- request-specific sync/async context factories
- sync/async scan callbacks
- configurable `allow` or `block` behavior for unscannable bodies
- typed skip reasons in ASGI state when allowed

Fail-closed handling should only be enabled on routes whose body schema is known. Empty bodies remain pass-through.

## Evaluation

A versioned corpus is a set of `EvaluationCase` labels. `evaluate()` reports:

- confusion matrix
- precision and recall
- false-positive rate and accuracy
- false-positive/negative IDs
- per-category recall
- p95 scan latency

Detection is evaluated at a single enforcement threshold (default
`DISABLE_TOOL_CALLS`): a case is "acted on" when its raw L4 decision reaches
that threshold. Precision, recall, and false-positive rate are all computed
against that one threshold, so a degenerate detector cannot score perfectly.
The full per-decision distribution is reported alongside for transparency.

The compact bundled `promptlint/corpora/regression-v0.2.json` corpus is a CI regression gate, not a broad efficacy benchmark. Claims about real-world performance require larger independent data and documented licensing/methodology.

## Test taxonomy

- attack rules: at least one focused positive per L1 rule
- hard negatives: legitimate educational, debugging, creative, multilingual, and operational text
- full-pipeline hard negatives: quoted cases allowed to match L1 but prohibited from blocking/escalating
- policy scenarios: realistic source/tool/task interactions
- canonicalization regressions: transform, projection, nesting, and confusable cases
- evaluation gate: precision/recall/FPR regression protection
- performance tests: benign, attack, and long-input latency
- middleware tests: extraction, role mapping, aggregation, callbacks, context, and unscannable behavior

## Conventions

- Use severity ordering only for compatibility decision aggregation.
- Preserve `Finding` evidence and `ActionConstraints` separately.
- Custom rules extend built-ins.
- Rule IDs are unique and stable.
- Rule patterns remain google-re2 compatible and bounded where possible.
- Unknown source/tier/trust values fail loudly.
- Package version comes from installed distribution metadata.
- Rule/scoring/policy changes update the evaluation corpus and report metric deltas.

## Monitoring

promptlint never phones home. Integrations should collect aggregate security telemetry without storing sensitive raw text by default:

- decisions and action constraints
- risk-score distribution
- top rule IDs/categories/dimensions
- false-positive/negative labels from review
- engine and degraded status
- p95 latency
- evaluation metric deltas by release
- unscannable body reasons

Deploy in monitor mode first, evaluate representative traffic, configure every tool tier, and only then enable enforcement.
