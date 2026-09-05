# Contributing

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gate

Run the same checks as CI before opening a pull request:

```bash
ruff check .
mypy promptlint
pytest --cov=promptlint
python -m build
python -m twine check dist/*
pip-audit
```

## Behavioral changes use tests first

For a rule, scorer, canonicalizer, policy, or middleware behavior change:

1. Add the smallest failing regression test.
2. Run that test and confirm the expected failure.
3. Implement the narrow behavior.
4. Run the focused test, then the full suite.
5. Run the versioned evaluation corpus and inspect metric deltas.

Do not weaken a hard negative merely to make a new rule pass. If legitimate quoted/debugging text matches a high-severity rule, preserve the original fixture and test the complete pipeline with explicit context.

## Adding an L1 rule

Add the rule to `promptlint/rules.yaml` using a unique ID and a google-re2-compatible expression. Then add:

- a positive case in `tests/test_attack_rules.py`
- hard negatives that exercise plausible legitimate uses
- a realistic policy scenario when source or tool capability matters
- a labeled case in `promptlint/corpora/regression-v0.2.json`

Use bounded patterns such as `[^\n]{0,80}` instead of unbounded `.*` where possible. Calibrate severity from behavior and corpus metrics rather than intuition alone.

## Evaluation corpus

Each JSON case requires:

```json
{
  "id": "unique-stable-id",
  "text": "input text",
  "expected_attack": true,
  "category": "instruction_override",
  "source": "tool_output",
  "available_tools": ["shell"],
  "user_task": "optional task context"
}
```

Run the gate:

```bash
promptlint evaluate \
  --min-recall 0.875 \
  --max-false-positive-rate 0.125
```

The compact in-repo corpus is for regression protection. Claims about broad effectiveness need a larger independent benchmark, clear dataset licensing, and reproducible methodology.

## Architecture invariants

- L0 normalizes and annotates; it does not decide.
- L1 detects signatures; it does not mutate input or decide policy.
- L2 scores textual evidence; mitigations are bounded.
- L4 owns trust, capability, and operating-mode decisions.
- A source describes provenance, not trust.
- Attacker-controlled text cannot waive critical findings.
- Unknown capabilities fail conservatively.
- `Finding` evidence remains separate from `ActionConstraints`.
- Original-position projection must remain valid after every transform.
- Public API changes require changelog and migration notes.
