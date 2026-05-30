# promptlint — Domain Context

This file defines the shared vocabulary for promptlint. It exists so agents,
reviewers, and contributors use consistent terms when discussing architecture,
tests, and behavior.

## Architecture Layers

**L0 — Canonicalization**
Pre-processing layer. Normalizes input text to strip obfuscation without
changing meaning. Produces `normalized` text for L1, an `offset_map` that
translates positions back to the original, and `annotations` recording
encoding tricks found (zero-width chars, URL encoding, ANSI escapes, bidi
controls). L0 never makes risk decisions.

**L1 — Regex Signatures**
Fast pattern-matching layer. Runs 20 built-in regex rules against
canonicalized text using google-re2 (or regex with timeout fallback).
Produces `Span` objects in *normalized coordinates*. Each span carries the
matched rule ID, severity, and category. L1 never modifies text.

**L2 — Contextual Scoring**
Composite risk scoring from 6 heuristic signals: instruction density,
authority claims, encoding suspicion, quoted context, semantic shift, and
task explanation detection. Combines L1 match severity with signal scores
via fixed weighted sum. Produces a 0.0–1.0 composite score and signal
breakdown. L2 never makes policy decisions.

**L3 — LLM Classifier (DEFERRED)**
Not shipped in v0. Reserved for future ML-based classification.

**L4 — Policy Engine**
Decision layer. Maps composite scores to 8 decision levels across 4 risk
bands (0.30/0.60/0.80). Incorporates source trust, tool capability tier,
quoted context, and task explanation. Applies mode post-filter
(monitor/block/paranoid). L4 owns all context-aware decision logic.

## Core Types

**Source** — Where scanned text originated. Affects L4 trust weighting.
Values: `user_direct`, `retrieved_document`, `tool_output`, `webpage`,
`email`, `log`. User-direct is baseline (most risky); log and email are
demoted one decision level.

**Decision** — L4 output, ordered least to most restrictive:
`ALLOW` → `ALLOW_WITH_WARNING` → `ALLOW_AS_QUOTED_DATA` →
`DISABLE_TOOL_CALLS` → `REDACT_SPANS` →
`REQUIRE_USER_CONFIRMATION` → `BLOCK` → `ESCALATE_TO_HUMAN`

**Tool Tier** — Capability classification for L4 escalation:
`read_only` → `network` → `write` → `elevated`.
Higher tiers mean more dangerous tools → stricter decisions at same score.

**Mode** — Operational post-filter on L4 decisions:
- `monitor`: Never block. Maps BLOCK/ESCALATE to ALLOW_WITH_WARNING.
- `block`: Normal operation. Decisions pass through unchanged.
- `paranoid`: Escalated. ALLOW → ALLOW_WITH_WARNING → ALLOW_AS_QUOTED_DATA.

**Span** — A detected suspicious text region with start/end positions,
risk_score, reason, and matched rule IDs. Spans from L1 are in normalized
coordinates; spans on ScanResult are translated to original coordinates.

**Safe Text** — The `result.text.safe` field on ScanResult. Produced from
original text based on decision: pass-through, markdown-quoted spans,
redacted spans, or [BLOCKED]/[ESCALATED].

**AppContext** — Application context passed to scan():
`available_tools` (tool names → tier classification), `user_task` (what the
user is trying to do, for task-explanation mitigation).

## Test Taxonomy

**Attack tests** — Known injection patterns that SHOULD trigger detection.
20 cases, one per L1 rule. Gate: L4 decision >= ALLOW_WITH_WARNING.

**Hard negatives** — Legitimate messages that MUST NOT be blocked.
25 cases: students studying attacks, developers debugging, creative writing,
non-English, code comments, etc. Gate: zero BLOCK, ESCALATE_TO_HUMAN,
or REQUIRE_USER_CONFIRMATION through full pipeline.

**Policy scenarios** — End-to-end tests exercising specific architecture
decisions: direct injection vs retrieved doc poisoning vs task explanation
vs tool escalation vs paranoid mode.

**Performance benchmarks** — p50/p95 timing for benign, attack, and long
text. Not gated; published for transparency.

## Conventions

- L1 spans are always in normalized coordinates. L0's `translate_spans()`
  converts to original coordinates before surfacing to callers.
- Safe-text production operates on original coordinates (not normalized).
  This is enforced by the span translation step in Firewall.scan().
- Decision aggregation uses severity ordering (DECISION_SEVERITY), not
  risk score. Worst decision wins in multi-field scans.
- Unknown tools default to read_only with a one-time warning. Custom tiers
  must use valid tier names (read_only/network/write/elevated).
- Invalid source values raise ValueError (fail-loud). Invalid tool_tier
  values raise ValueError inside L4 decide().
- `ScanResult.l4_decision` is the raw L4 output before mode filtering.
  `ScanResult.decision` is the mode-filtered result callers should act on.

## Monitoring & Data Collection

promptlint is an observability-first library. It does NOT phone home or send
data anywhere. Instead, it gives you the hooks to wire it into your own
monitoring stack.

### Monitor mode — safe deployment

Deploy in `monitor` mode first. The library **never blocks** in this mode —
requests pass through regardless of scan results. This lets you measure
false-positive rates on live traffic without any risk to users:

```python
fw = Firewall(mode="monitor")
result = fw.scan(user_input)
# result.decision may be BLOCK, but nothing is actually blocked
```

### Structured JSON logging

Every component logs as JSON-per-line (container-ready, stdout). Configure
Python logging to capture:

```python
from promptlint.logging import setup_logging
setup_logging()

# Logs appear as:
# {"timestamp": "2026-05-29T21:00:00", "level": "INFO", "logger": "promptlint.l1.engine",
#  "message": "L1 engine: google-re2 — 20 rules loaded"}
```

Ship these to your logging backend (Datadog, Grafana Loki, CloudWatch, ELK).

### Middleware callback

The FastAPI middleware accepts an `on_scan` callback that fires after every
scan. Use it to increment counters, sample results, or write to a metrics
backend:

```python
from datadog import statsd

def track_scan(result):
    statsd.increment("promptlint.scans", tags=[f"decision:{result.decision.value}"])
    statsd.histogram("promptlint.score", result.risk_score)

app.add_middleware(
    PromptlintMiddleware,
    firewall=Firewall(mode="monitor"),
    on_scan=track_scan,
)
```

### What to measure

| Metric | Why |
|--------|-----|
| Scans per decision (ALLOW / ALLOW_WITH_WARNING / ...) | False positive rate |
| Risk score distribution | Are scores clustering at thresholds? |
| Top-matched rule IDs | Which rules fire most? Are they correct? |
| Engine degraded flag | Is re2 available in production? |
| p95 scan latency | Performance regression detection |
| Hard negative pass rate | Are the 25 benchmarks still green? |

### Sharing feedback

If you deploy promptlint and want to help improve it, share aggregate stats
(not raw user data): decision distribution, top rules firing, false-positive
examples you're comfortable sharing. Open an issue or PR on the repo.

### Graduating to block mode

When your monitor-mode data shows zero false positives over a meaningful
period (days to weeks, depending on traffic), switch to block mode:

```python
fw = Firewall(mode="block")
```

Keep the monitoring hooks. Block mode doesn't mean stop watching.
