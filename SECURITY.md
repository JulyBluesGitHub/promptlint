# Security Policy

## What promptlint is

promptlint is a fast, deterministic detection and policy signal for common prompt-injection patterns. It is useful for observability, obvious-attack filtering, regression testing, and restricting tools when suspicious text is encountered.

## What promptlint is not

promptlint is not a complete security boundary. An attacker can paraphrase, translate, encode, split, or adapt an injection beyond static signatures and heuristics. A clean result does not prove that text is safe, and a matched result does not prove malicious intent.

Do not put secrets in prompts when they can be kept outside the model context. Do not authorize an action solely because model-generated text requested it.

## Threat model

promptlint considers these inputs potentially attacker-controlled unless the integrating application explicitly proves otherwise:

- direct user messages
- retrieved documents and RAG chunks
- web pages and browser output
- email and attachments
- logs and issue text
- tool output and dependency source code
- model-generated content replayed into another model or agent

A `source` value records provenance; it does not grant trust. `AppContext.content_trust="trusted"` is an explicit application assertion and must only be used for authenticated content whose integrity and origin are enforced outside the model.

## Required defense in depth

Production agent systems should also enforce:

1. Least-privilege, task-scoped tool access.
2. Authorization and parameter validation in deterministic application code.
3. Human approval for financial, destructive, privileged, or external-communication actions.
4. Egress allowlists and disabled automatic loading of remote content.
5. Structured model outputs with schema validation.
6. Output filtering for secrets, credentials, and unintended data disclosure.
7. Isolation between untrusted content processing and privileged action planning.
8. Security logging, monitor-mode rollout, and evaluation against representative traffic.

## Safe deployment

1. Start with `Firewall(mode="monitor")`.
2. Record aggregate decisions, rule IDs, latency, and manually labeled false positives/negatives. Avoid storing raw sensitive text.
3. Run a versioned evaluation corpus before changing rules, weights, or thresholds.
4. Configure every application tool tier. Unknown tools default to `write`, but explicit classification is better.
5. Enable block mode only after reviewing behavior on your traffic.
6. Treat unscannable middleware inputs explicitly; use fail-closed behavior only on routes with known request schemas.

## Supported versions

Security fixes are released on the latest minor version. Upgrade to the newest published release before reporting an issue.

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability that is not already public. Use GitHub's private vulnerability reporting for this repository:

https://github.com/JulyBluesGitHub/promptlint/security/advisories/new

Include:

- affected promptlint version
- minimal reproducer
- expected and actual decisions/findings
- source and tool context
- impact and proposed mitigation, if known

Reports about a detector bypass are most actionable when they demonstrate impact in a realistic integration. Because prompt injection is an open-ended problem, an unmatched phrase by itself may be handled as an evaluation-corpus improvement rather than a security vulnerability.
