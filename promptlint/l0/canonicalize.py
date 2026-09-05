"""L0 canonicalization — normalize text, strip obfuscation, detect encoding tricks.

Produces CanonicalizationResult with:
  - normalized text for L1 scanning
  - offset_map: list of (canonical_pos, original_pos) for translating matches back
  - annotations: encoding tricks found but not necessarily dangerous
"""

from __future__ import annotations

import html
import re
import unicodedata
import urllib.parse

from promptlint.types import Annotation, CanonicalizationResult

# Zero-width and invisible characters (NOT including bidi controls)
ZERO_WIDTH_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    "\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5"
    "\u180b\u180c\u180d\u180e"
    "\u206a\u206b\u206c\u206d\u206e\u206f"
    "\uffa0]+",
)

# Visible or line-breaking separators that must become a space, not vanish
# (U+2028/2029 line/paragraph separators, U+205F medium math space, U+2800 braille blank).
SEPARATOR_CHARS = re.compile("[\u2028\u2029\u205f\u2800]")


# ANSI escape sequences
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Bidi control characters
BIDI_CONTROLS = re.compile("[\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]")

# High-confidence Cyrillic/Greek glyphs commonly substituted for ASCII.
# This is deliberately conservative rather than a general transliterator.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "і": "i",
        "ј": "j",
        "о": "o",
        "р": "p",
        "с": "c",
        "ѕ": "s",
        "у": "y",
        "х": "x",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        "ο": "o",
        "ρ": "p",
        "ι": "i",
        "κ": "k",
    }
)


def canonicalize(
    text: str,
    *,
    max_decode_passes: int = 4,
) -> CanonicalizationResult:
    """Apply all L0 canonicalization transforms with offset tracking.

    URL and HTML entity decoding run to a bounded fixed point so nested
    encodings cannot bypass L1 signatures. ``truncated`` is set when the
    configured pass budget is exhausted while decoding is still changing.
    """
    if max_decode_passes < 1:
        raise ValueError("max_decode_passes must be at least 1")

    original = text
    annotations: list[Annotation] = []
    decode_budget_exhausted = False

    # Track position: we'll rebuild offset_map after all transforms.
    # Strategy: record (canonical_pos, original_pos) for every character,
    # then apply transforms and track how positions shift.

    # Build initial offset map — positions are identity until transforms
    offset_map: list[tuple[int, int]] = [(i, i) for i in range(len(text))]

    # 1. NFKD normalize (handles compatibility forms and composed chars)
    text, offset_map = _nfkd_normalize(text, offset_map)

    # 1a. Strip combining marks produced by NFKD decomposition (ō -> o + U+0304).
    text, offset_map, combining_annotations = _strip_combining_marks(text, offset_map)
    annotations.extend(combining_annotations)

    # 1b. Replace high-confidence cross-script lookalikes.
    text, confusable_annotations = _skeletonize_confusables(text, offset_map)
    annotations.extend(confusable_annotations)

    # 2–3. Decode nested URL and HTML entities to a bounded fixed point.
    for pass_index in range(max_decode_passes):
        before = text
        text, offset_map, url_annotations = _decode_url_entities(text, offset_map)
        annotations.extend(url_annotations)
        text, offset_map, html_annotations = _decode_html_entities(text, offset_map)
        annotations.extend(html_annotations)
        text, confusable_annotations = _skeletonize_confusables(text, offset_map)
        annotations.extend(confusable_annotations)
        if text == before:
            break
        if pass_index == max_decode_passes - 1:
            decode_budget_exhausted = (
                urllib.parse.unquote(text) != text or html.unescape(text) != text
            )

    # 4. Detect bidi control chars (do this BEFORE stripping, since some overlap)
    bidi_annotations = _detect_bidi(text, offset_map)
    annotations.extend(bidi_annotations)

    # 5. Strip zero-width chars (record annotations)
    text, offset_map, zw_annotations = _strip_zero_width(text, offset_map)
    annotations.extend(zw_annotations)

    # 5b. Replace visible/line-breaking separators with spaces (1:1, map intact).
    text, offset_map, sep_annotations = _replace_separators(text, offset_map)
    annotations.extend(sep_annotations)

    # 6. Strip ANSI escapes (record annotations)
    text, offset_map, ansi_annotations = _strip_ansi(text, offset_map)
    annotations.extend(ansi_annotations)

    return CanonicalizationResult(
        original=original,
        normalized=text,
        offset_map=offset_map,
        annotations=annotations,
        truncated=decode_budget_exhausted,
    )


def _nfkd_normalize(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]]]:
    """NFKD normalize — maps composed characters to decomposed equivalents."""
    result_chars: list[str] = []
    new_map: list[tuple[int, int]] = []

    for _, (_, orig_pos) in enumerate(offset_map):
        ch = text[orig_pos]
        normalized = unicodedata.normalize("NFKD", ch)
        for nch in normalized:
            result_chars.append(nch)
            new_map.append((len(new_map), orig_pos))

    return "".join(result_chars), new_map


def _skeletonize_confusables(
    text: str,
    offset_map: list[tuple[int, int]],
) -> tuple[str, list[Annotation]]:
    """Map conservative cross-script lookalikes to an ASCII skeleton."""
    annotations: list[Annotation] = []
    translated: list[str] = []
    for pos, char in enumerate(text):
        replacement = char.translate(CONFUSABLES)
        translated.append(replacement)
        if replacement != char:
            original_pos = offset_map[pos][1] if pos < len(offset_map) else pos
            annotations.append(
                Annotation(
                    type="confusable",
                    start=original_pos,
                    end=original_pos + 1,
                    detail=f"U+{ord(char):04X} mapped to {replacement!r}",
                )
            )
    return "".join(translated), annotations


def _strip_combining_marks(
    text: str,
    offset_map: list[tuple[int, int]],
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Remove Unicode combining marks (Mn/Mc/Me) left by NFKD decomposition."""
    annotations: list[Annotation] = []
    result_chars: list[str] = []
    new_map: list[tuple[int, int]] = []
    for canonical_pos, (_, orig_pos) in enumerate(offset_map):
        ch = text[canonical_pos]
        if unicodedata.combining(ch):
            annotations.append(
                Annotation(
                    type="combining_mark",
                    start=canonical_pos,
                    end=canonical_pos + 1,
                    detail=f"U+{ord(ch):04X}",
                )
            )
        else:
            result_chars.append(ch)
            new_map.append((len(new_map), orig_pos))
    return "".join(result_chars), new_map, annotations


def _replace_separators(
    text: str,
    offset_map: list[tuple[int, int]],
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Replace visible/line-breaking separators with spaces (1:1 substitution)."""
    annotations: list[Annotation] = []
    for m in SEPARATOR_CHARS.finditer(text):
        original_pos = offset_map[m.start()][1] if m.start() < len(offset_map) else m.start()
        annotations.append(
            Annotation(
                type="separator",
                start=original_pos,
                end=original_pos + 1,
                detail=f"U+{ord(m.group()):04X} replaced with space",
            )
        )
    replaced = SEPARATOR_CHARS.sub(" ", text)
    return replaced, offset_map, annotations


def _decode_url_entities(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Decode URL-encoded sequences (%20 → space, etc)."""
    annotations: list[Annotation] = []
    result_chars: list[str] = []
    new_map: list[tuple[int, int]] = []

    def is_pct_encoded(pos: int) -> bool:
        return (
            pos + 2 < len(text)
            and text[pos] == "%"
            and all(ch in "0123456789ABCDEFabcdef" for ch in text[pos + 1 : pos + 3])
        )

    i = 0
    while i < len(text):
        if is_pct_encoded(i):
            start = i
            token_starts: list[int] = []
            while i < len(text) and is_pct_encoded(i):
                token_starts.append(i)
                i += 3

            encoded = text[start:i]
            decoded = urllib.parse.unquote(encoded)
            if decoded != encoded:
                for token_start in token_starts:
                    token = text[token_start : token_start + 3]
                    annotations.append(
                        Annotation(
                            type="url_encoded",
                            start=token_start,
                            end=token_start + 3,
                            detail=f"decoded '{token}' → '{urllib.parse.unquote(token)}'",
                        )
                    )

            if len(decoded) == len(token_starts):
                original_positions = [
                    offset_map[token_start][1]
                    for token_start in token_starts
                    if token_start < len(offset_map)
                ]
            else:
                original_positions = [
                    offset_map[start][1] if start < len(offset_map) else start
                ] * len(decoded)

            for decoded_index, ch in enumerate(decoded):
                result_chars.append(ch)
                original_pos = (
                    original_positions[decoded_index]
                    if decoded_index < len(original_positions)
                    else start
                )
                new_map.append((len(new_map), original_pos))
        else:
            result_chars.append(text[i])
            original_pos = offset_map[i][1] if i < len(offset_map) else i
            new_map.append((len(new_map), original_pos))
            i += 1

    return "".join(result_chars), new_map, annotations


def _decode_html_entities(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Decode HTML entities (&amp; → &, &#x27; → ', etc)."""
    annotations: list[Annotation] = []
    result_chars: list[str] = []
    new_map: list[tuple[int, int]] = []

    entity_pattern = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+);?|&[A-Za-z][A-Za-z0-9]+;")
    last_end = 0

    def append_original_segment(start: int, end: int) -> None:
        for pos in range(start, end):
            result_chars.append(text[pos])
            original_pos = offset_map[pos][1] if pos < len(offset_map) else pos
            new_map.append((len(new_map), original_pos))

    for m in entity_pattern.finditer(text):
        append_original_segment(last_end, m.start())

        entity = m.group()
        decoded = html.unescape(entity)
        if decoded != entity:
            annotations.append(
                Annotation(
                    type="url_encoded",  # reuse type — it's an encoding trick
                    start=m.start(),
                    end=m.end(),
                    detail=f"html entity '{entity}' decoded",
                )
            )
            original_pos = offset_map[m.start()][1] if m.start() < len(offset_map) else m.start()
            for ch in decoded:
                result_chars.append(ch)
                new_map.append((len(new_map), original_pos))
        else:
            append_original_segment(m.start(), m.end())

        last_end = m.end()

    append_original_segment(last_end, len(text))

    return "".join(result_chars), new_map, annotations


def _strip_zero_width(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Remove zero-width and invisible characters, recording annotations."""
    annotations: list[Annotation] = []
    result_chars: list[str] = []
    new_map: list[tuple[int, int]] = []

    for canonical_pos, (_, orig_pos) in enumerate(offset_map):
        if canonical_pos >= len(text):
            break
        ch = text[canonical_pos]
        if ZERO_WIDTH_CHARS.match(ch):
            annotations.append(
                Annotation(
                    type="zero_width_chars",
                    start=canonical_pos,
                    end=canonical_pos + 1,
                    detail=f"U+{ord(ch):04X}",
                )
            )
        else:
            result_chars.append(ch)
            new_map.append((len(new_map), orig_pos))

    return "".join(result_chars), new_map, annotations


def _strip_ansi(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Remove ANSI escape sequences."""
    annotations: list[Annotation] = []
    result = text
    new_map = list(offset_map)

    for m in ANSI_ESCAPE.finditer(text):
        annotations.append(
            Annotation(
                type="ansi_escape",
                start=m.start(),
                end=m.end(),
                detail="ANSI escape removed",
            )
        )

    clean = ANSI_ESCAPE.sub("", text)
    if clean != text:
        result = clean
        new_map = _rebuild_offset_map_linear(text, clean, offset_map)

    return result, new_map, annotations


def _detect_bidi(text: str, offset_map: list[tuple[int, int]]) -> list[Annotation]:
    """Detect bidirectional control characters (potential Trojan Source attacks)."""
    annotations: list[Annotation] = []
    for m in BIDI_CONTROLS.finditer(text):
        annotations.append(
            Annotation(
                type="bidi_control",
                start=m.start(),
                end=m.end(),
                detail=f"U+{ord(m.group()):04X} bidi control",
            )
        )
    return annotations


def _rebuild_offset_map_linear(
    original: str, transformed: str, original_map: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Rebuild offset map after a length-changing transformation.

    Strategy: walk both strings in lockstep, mapping each transformed char
    to the nearest original position from the original map.
    """
    if not original:
        return []

    new_map: list[tuple[int, int]] = []
    orig_idx = 0
    orig_len = len(original)

    for t_idx, t_ch in enumerate(transformed):
        # Advance original index to find matching char
        while orig_idx < orig_len and original[orig_idx] != t_ch:
            orig_idx += 1
        if orig_idx < orig_len:
            _, orig_pos = (
                original_map[orig_idx] if orig_idx < len(original_map) else (orig_idx, orig_idx)
            )
            new_map.append((t_idx, orig_pos))
            orig_idx += 1
        else:
            # Fallback: use last known position
            new_map.append((t_idx, original_map[-1][1] if original_map else 0))

    return new_map
