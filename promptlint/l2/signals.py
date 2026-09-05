"""L2 contextual scoring signals.

Six heuristics that contribute to the composite risk score.
All are source-agnostic text analysis only.
"""

from __future__ import annotations

import re

from promptlint.types import Annotation, Span

# Imperative verbs commonly used in injection attacks
IMPERATIVE_VERBS = re.compile(
    r"\b(?:ignore|disregard|override|bypass|reveal|show|print|dump|"
    r"delete|execute|run|decode|output|forget|wipe|clear|reset|erase|"
    r"terminate|expose|extract|steal|copy|repeat)\b",
    re.IGNORECASE,
)

# Destructive-action verbs — a focused subset of imperatives that signal
# data/code destruction rather than just reading or revealing.
# Presence of these verbs, especially in non-user-direct sources with
# write tools available, sharply elevates risk.
DESTRUCTIVE_VERBS = re.compile(
    r"\b(?:delete|wipe|rm\b|erase|destroy|purge|nuke|shred|trash"
    r"|obliterate|annihilate|remove\s+all|clear\s+all)\b",
    re.IGNORECASE,
)

# Authority-claiming phrases
AUTHORITY_PATTERNS = [
    re.compile(r"you (?:must|have to|need to|are required to|shall)", re.IGNORECASE),
    re.compile(r"(?:new directive|new instruction|new rule|new command|new order)", re.IGNORECASE),
    re.compile(r"(?:from now on|starting now|as of now)", re.IGNORECASE),
    re.compile(
        r"(?:I am (?:your|the) (?:creator|owner|admin|master|commander|boss))", re.IGNORECASE
    ),
    re.compile(r"\b(?:sudo|root|admin|superuser)\b", re.IGNORECASE),
]

# Narrative framing patterns (simulation, game, hypothetical)
NARRATIVE_PATTERNS = [
    re.compile(r"(?:hypothetical|pretend|imagine|simulation|game|role.?play)", re.IGNORECASE),
    re.compile(r"(?:what if|let's say|suppose)", re.IGNORECASE),
    re.compile(r"(?:you are no longer|you are now|you have become)", re.IGNORECASE),
    re.compile(r"(?:in a world|in a scenario|in this story)", re.IGNORECASE),
]

# Quoted/code region indicators
QUOTE_INDICATORS = re.compile(
    r'(?:"[^"]{3,}"|'  # double-quoted strings
    r"'[^']{3,}'|"  # single-quoted strings
    r"`[^`]{3,}`|"  # backtick strings
    r"```[\s\S]*?```|"  # code blocks
    r"^\s{4,}|\t)",  # indented code
    re.MULTILINE,
)

# Task-explanation heuristic patterns
TASK_EXPLANATION_PATTERNS = [
    re.compile(r"(?:can you explain|why|what is|how does|tell me about)", re.IGNORECASE),
    re.compile(r"(?:is this (?:safe|dangerous|a problem|an attack))", re.IGNORECASE),
    re.compile(r"\b(?:debug|investigate|analyze|review|check)\b", re.IGNORECASE),
    re.compile(r"(?:I (?:don't|do not) understand)", re.IGNORECASE),
    re.compile(r"(?:help me|can you help|please explain)", re.IGNORECASE),
    re.compile(r"(?:is it normal|is it expected|should I be)", re.IGNORECASE),
]

# Words that don't identify specific content: deictics, stopwords, and the
# review/explain cue verbs themselves. Excluded from the task↔text token
# overlap so a bare "review this email" cannot satisfy the reference check.
_TASK_REFERENCE_STOPWORDS = frozenset(
    {
        "this",
        "that",
        "these",
        "those",
        "there",
        "here",
        "your",
        "you",
        "the",
        "and",
        "for",
        "with",
        "from",
        "about",
        "what",
        "when",
        "where",
        "why",
        "how",
        "please",
        "would",
        "could",
        "should",
        "have",
        "been",
        "into",
        "like",
        "such",
        "their",
        "them",
        "they",
        "more",
        "does",
        "explain",
        "review",
        "check",
        "debug",
        "analyze",
        "investigate",
        "understand",
        "help",
        "tell",
        "normal",
        "expected",
    }
)


def _content_tokens(text: str) -> set[str]:
    """Lowercased content words (>=4 letters) excluding deictics/stopwords."""
    return {
        token
        for token in re.findall(r"\b[a-z]{4,}\b", text.lower())
        if token not in _TASK_REFERENCE_STOPWORDS
    }


def instruction_density(text: str) -> float:
    """Ratio of imperative verb occurrences to total word count. Capped at 1.0."""
    words = text.split()
    if not words:
        return 0.0
    imperative_count = len(IMPERATIVE_VERBS.findall(text))
    density = imperative_count / len(words)
    return min(density * 5.0, 1.0)  # scale: 1 imperative per 5 words → 1.0


def destructive_verbs(text: str) -> float:
    """Presence and density of destructive-action verbs. Capped at 1.0.

    Unlike instruction_density which counts all imperatives equally,
    this signal isolates verbs that explicitly destroy data, code, or state.
    Scaling: 1 destructive verb = 0.5, 2+ = 1.0 — presence matters more
    than density for destructive payloads (even one "delete all files" is dangerous).
    """
    if not text:
        return 0.0
    count = len(DESTRUCTIVE_VERBS.findall(text))
    if count == 0:
        return 0.0
    return min(count * 0.5, 1.0)


def authority_claims(text: str) -> float:
    """Density of authority-claiming patterns. Capped at 1.0."""
    score = 0.0
    for pattern in AUTHORITY_PATTERNS:
        if pattern.search(text):
            score += 0.25
    return min(score, 1.0)


def encoding_suspicion(annotations: list[Annotation]) -> float:
    """L0 annotation density as a suspicion signal. Capped at 1.0."""
    if not annotations:
        return 0.0
    # Each annotation type contributes; more types = more suspicious
    types_seen = len({a.type for a in annotations})
    score = types_seen * 0.25 + min(len(annotations) * 0.05, 0.25)
    return min(score, 1.0)


def quoted_context(text: str, spans: list[Span]) -> float:
    """What fraction of matched spans fall inside quoted/code regions?

    Returns 0.0–1.0 where 1.0 means all matched spans are in quoted context,
    which reduces the risk score (high quoted = high mitigation).
    """
    if not spans:
        return 0.0

    # Find all quoted/code intervals in the text
    quote_regions: list[tuple[int, int]] = []
    for m in QUOTE_INDICATORS.finditer(text):
        quote_regions.append((m.start(), m.end()))

    if not quote_regions:
        return 0.0

    quoted_spans = 0
    for span in spans:
        for q_start, q_end in quote_regions:
            if q_start <= span.start and span.end <= q_end:
                quoted_spans += 1
                break

    return quoted_spans / len(spans)


def semantic_shift(text: str) -> float:
    """Detect narrative framing / context-shift patterns. Capped at 1.0."""
    score = 0.0
    for pattern in NARRATIVE_PATTERNS:
        if pattern.search(text):
            score += 0.25
    return min(score, 1.0)


def task_explains_content(user_task: str, text: str) -> bool:
    """Does the user's stated task explain why suspicious content is present?

    True only when the task (a) uses an explain/review/debug/check cue AND
    (b) references content that actually appears in the scanned text. A bare
    "review this email" that names nothing in the payload is not enough — it is
    cheaply satisfied by a predictable user prompt alongside an
    attacker-controlled quoted payload.
    """
    if not user_task or not text:
        return False
    if not any(pattern.search(user_task) for pattern in TASK_EXPLANATION_PATTERNS):
        return False
    return bool(_content_tokens(user_task) & _content_tokens(text))
