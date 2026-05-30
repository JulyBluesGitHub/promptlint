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
from typing import Any

from promptlint.types import Annotation, CanonicalizationResult


# Zero-width and invisible characters (NOT including bidi controls)
ZERO_WIDTH_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    "\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5"
    "\u180b\u180c\u180d\u180e\u2000\u2001\u2002\u2003"
    "\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028"
    "\u2029\u205f"
    "\u206a\u206b\u206c\u206d\u206e\u206f"
    "\u2800\uffa0]+",
)


# ANSI escape sequences
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Bidi control characters
BIDI_CONTROLS = re.compile("[\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]")


def canonicalize(text: str) -> CanonicalizationResult:
    """Apply all L0 canonicalization transforms with offset tracking."""
    original = text
    annotations: list[Annotation] = []

    # Track position: we'll rebuild offset_map after all transforms.
    # Strategy: record (canonical_pos, original_pos) for every character,
    # then apply transforms and track how positions shift.

    # Build initial offset map — positions are identity until transforms
    offset_map: list[tuple[int, int]] = [(i, i) for i in range(len(text))]

    # 1. NFKD normalize (handles homoglyphs, composed chars)
    text, offset_map = _nfkd_normalize(text, offset_map)

    # 2. URL decode
    text, offset_map, url_annotations = _decode_url_entities(text, offset_map)
    annotations.extend(url_annotations)

    # 3. HTML entity decode
    text, offset_map, html_annotations = _decode_html_entities(text, offset_map)
    annotations.extend(html_annotations)

    # 4. Detect bidi control chars (do this BEFORE stripping, since some overlap)
    bidi_annotations = _detect_bidi(text, offset_map)
    annotations.extend(bidi_annotations)

    # 5. Strip zero-width chars (record annotations)
    text, offset_map, zw_annotations = _strip_zero_width(text, offset_map)
    annotations.extend(zw_annotations)

    # 6. Strip ANSI escapes (record annotations)
    text, offset_map, ansi_annotations = _strip_ansi(text, offset_map)
    annotations.extend(ansi_annotations)

    return CanonicalizationResult(
        original=original,
        normalized=text,
        offset_map=offset_map,
        annotations=annotations,
        truncated=False,
    )


def _nfkd_normalize(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]]]:
    """NFKD normalize — maps composed characters to decomposed equivalents."""
    result_chars: list[str] = []
    new_map: list[tuple[int, int]] = []

    for canonical_pos, (_, orig_pos) in enumerate(offset_map):
        ch = text[orig_pos]
        normalized = unicodedata.normalize("NFKD", ch)
        for nch in normalized:
            result_chars.append(nch)
            new_map.append((len(new_map), orig_pos))

    return "".join(result_chars), new_map


def _decode_url_entities(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Decode URL-encoded sequences (%20 → space, etc)."""
    annotations: list[Annotation] = []
    result = text
    new_map = list(offset_map)

    # Find URL-encoded sequences
    url_pattern = re.compile(r"%[0-9A-Fa-f]{2}")
    for m in url_pattern.finditer(text):
        try:
            decoded = urllib.parse.unquote(m.group())
            if decoded != m.group():
                annotations.append(
                    Annotation(
                        type="url_encoded",
                        start=m.start(),
                        end=m.end(),
                        detail=f"decoded '{m.group()}' → '{decoded}'",
                    )
                )
        except Exception:
            pass

    # Actually decode
    decoded_text = urllib.parse.unquote(text)
    if decoded_text != text:
        result = decoded_text
        # Rebuild offset map: any char that was %XX maps to same original pos
        new_map = _rebuild_offset_map_linear(text, result, offset_map)

    return result, new_map, annotations


def _decode_html_entities(
    text: str, offset_map: list[tuple[int, int]]
) -> tuple[str, list[tuple[int, int]], list[Annotation]]:
    """Decode HTML entities (&amp; → &, &#x27; → ', etc)."""
    annotations: list[Annotation] = []
    decoded = html.unescape(text)
    new_map = list(offset_map)

    if decoded != text:
        # Find entities that were decoded
        entity_pattern = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|\w+);")
        for m in entity_pattern.finditer(text):
            annotations.append(
                Annotation(
                    type="url_encoded",  # reuse type — it's an encoding trick
                    start=m.start(),
                    end=m.end(),
                    detail=f"html entity '{m.group()}' decoded",
                )
            )
        new_map = _rebuild_offset_map_linear(text, decoded, offset_map)

    return decoded, new_map, annotations


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
                detail=f"ANSI escape removed",
            )
        )

    clean = ANSI_ESCAPE.sub("", text)
    if clean != text:
        result = clean
        new_map = _rebuild_offset_map_linear(text, clean, offset_map)

    return result, new_map, annotations


def _detect_bidi(
    text: str, offset_map: list[tuple[int, int]]
) -> list[Annotation]:
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
            _, orig_pos = original_map[orig_idx] if orig_idx < len(original_map) else (orig_idx, orig_idx)
            new_map.append((t_idx, orig_pos))
            orig_idx += 1
        else:
            # Fallback: use last known position
            new_map.append((t_idx, original_map[-1][1] if original_map else 0))

    return new_map
