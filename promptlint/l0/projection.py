"""L0 span projection — translate normalized-coordinate spans back to original text.

L1 scans canonicalized text, producing spans in normalized coordinates.
These functions project those spans back to original text positions using
the offset_map produced by canonicalize().
"""

from __future__ import annotations

from promptlint.types import CanonicalizationResult, Span


def translate_spans(l0: CanonicalizationResult, spans: list[Span]) -> list[Span]:
    """Translate normalized-coordinate spans back to original text spans.

    The returned ``Span.text`` is the slice from ``l0.original`` covered by
    the projected range. Metadata from each input span is preserved.
    """
    translated: list[Span] = []
    for span in spans:
        projected = _project_span_range(span, l0)
        if projected is None:
            continue
        start, end = projected
        translated.append(
            Span(
                start=start,
                end=end,
                text=l0.original[start:end],
                risk_score=span.risk_score,
                reason=span.reason,
                matched_rules=list(span.matched_rules),
                source=span.source,
            )
        )
    return translated


def project_span_ranges(l0: CanonicalizationResult, spans: list[Span]) -> list[tuple[int, int]]:
    """Project normalized-coordinate spans to merged original text ranges."""
    ranges: list[tuple[int, int]] = []
    for span in spans:
        projected = _project_span_range(span, l0)
        if projected is not None:
            ranges.append(projected)
    return _merge_ranges(ranges)


def _project_span_range(span: Span, l0: CanonicalizationResult) -> tuple[int, int] | None:
    if span.end <= span.start:
        return None

    text_len = len(l0.original)
    if l0.offset_map:
        start = _original_boundary(span.start, l0.offset_map, text_len)
        end = _original_boundary(span.end, l0.offset_map, text_len)
        if end <= start:
            mapped_positions = [
                original_pos
                for _, original_pos in l0.offset_map[span.start:span.end]
            ]
            if mapped_positions:
                start = min(mapped_positions)
                end = max(mapped_positions) + 1
    else:
        start = span.start
        end = span.end

    start = max(0, min(start, text_len))
    end = max(start, min(end, text_len))
    if end <= start:
        return None
    return start, end


def _original_boundary(normalized_pos: int, offset_map: list[tuple[int, int]], text_len: int) -> int:
    if normalized_pos <= 0:
        return 0
    if normalized_pos >= len(offset_map):
        return text_len
    return offset_map[normalized_pos][1]


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
    return merged
