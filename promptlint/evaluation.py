"""Versioned evaluation harness for prompt-injection detection quality."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from promptlint.firewall import Firewall
from promptlint.types import AppContext


@dataclass(frozen=True)
class EvaluationCase:
    """One labeled input used to evaluate detection quality."""

    id: str
    text: str
    expected_attack: bool
    category: str | None = None
    source: str = "user_direct"
    available_tools: tuple[str, ...] = ()
    user_task: str = ""


@dataclass(frozen=True)
class EvaluationCorpus:
    """A versioned collection of labeled evaluation cases."""

    version: str
    cases: tuple[EvaluationCase, ...]
    description: str = ""


@dataclass(frozen=True)
class EvaluationReport:
    """Confusion matrix, rates, regressions, and latency for one run."""

    total: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    accuracy: float
    latency_p95_ms: float
    false_positive_ids: list[str] = field(default_factory=list)
    false_negative_ids: list[str] = field(default_factory=list)
    category_recall: dict[str, float] = field(default_factory=dict)


def evaluate(
    cases: Iterable[EvaluationCase],
    *,
    firewall: Firewall | None = None,
    decision_threshold: float = 0.30,
) -> EvaluationReport:
    """Evaluate cases against a firewall using a fixed risk threshold."""
    if not 0.0 <= decision_threshold <= 1.0:
        raise ValueError("decision_threshold must be between 0.0 and 1.0")

    scanner = firewall or Firewall(mode="block")
    case_list = list(cases)
    tp = tn = fp = fn = 0
    false_positive_ids: list[str] = []
    false_negative_ids: list[str] = []
    latencies: list[float] = []
    category_totals: dict[str, int] = {}
    category_hits: dict[str, int] = {}

    for case in case_list:
        started = time.perf_counter()
        result = scanner.scan(
            case.text,
            source=case.source,
            app_context=AppContext(
                available_tools=list(case.available_tools),
                user_task=case.user_task,
            ),
        )
        latencies.append((time.perf_counter() - started) * 1000)
        predicted_attack = result.risk_score >= decision_threshold

        if case.expected_attack:
            if case.category:
                category_totals[case.category] = category_totals.get(case.category, 0) + 1
            if predicted_attack:
                tp += 1
                if case.category:
                    category_hits[case.category] = category_hits.get(case.category, 0) + 1
            else:
                fn += 1
                false_negative_ids.append(case.id)
        elif predicted_attack:
            fp += 1
            false_positive_ids.append(case.id)
        else:
            tn += 1

    total = len(case_list)
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    false_positive_rate = _safe_ratio(fp, fp + tn)
    accuracy = _safe_ratio(tp + tn, total)
    category_recall = {
        category: _safe_ratio(category_hits.get(category, 0), count)
        for category, count in sorted(category_totals.items())
    }

    return EvaluationReport(
        total=total,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        false_positive_rate=round(false_positive_rate, 4),
        accuracy=round(accuracy, 4),
        latency_p95_ms=round(_percentile(latencies, 0.95), 4),
        false_positive_ids=false_positive_ids,
        false_negative_ids=false_negative_ids,
        category_recall=category_recall,
    )


def load_corpus(path: str | Path) -> EvaluationCorpus:
    """Load and validate a versioned JSON evaluation corpus."""
    corpus_path = Path(path)
    data: Any = json.loads(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Evaluation corpus must be a JSON object")
    version = data.get("version")
    raw_cases = data.get("cases")
    if not isinstance(version, str) or not version:
        raise ValueError("Evaluation corpus requires a non-empty string version")
    if not isinstance(raw_cases, list):
        raise ValueError("Evaluation corpus requires a cases list")

    cases: list[EvaluationCase] = []
    seen_ids: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise ValueError("Each evaluation case must be an object")
        case_id = raw.get("id")
        text = raw.get("text")
        expected_attack = raw.get("expected_attack")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("Each evaluation case requires a non-empty string id")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate evaluation case id: {case_id}")
        if not isinstance(text, str):
            raise ValueError(f"Evaluation case {case_id} requires string text")
        if not isinstance(expected_attack, bool):
            raise ValueError(f"Evaluation case {case_id} requires boolean expected_attack")
        seen_ids.add(case_id)
        cases.append(
            EvaluationCase(
                id=case_id,
                text=text,
                expected_attack=expected_attack,
                category=raw.get("category"),
                source=raw.get("source", "user_direct"),
                available_tools=tuple(raw.get("available_tools", ())),
                user_task=raw.get("user_task", ""),
            )
        )

    return EvaluationCorpus(
        version=version,
        description=str(data.get("description", "")),
        cases=tuple(cases),
    )


def load_builtin_corpus(name: str = "regression-v0.2") -> EvaluationCorpus:
    """Load a versioned corpus shipped as package data."""
    resource = files("promptlint").joinpath("corpora").joinpath(f"{name}.json")
    if not resource.is_file():
        raise FileNotFoundError(f"Unknown built-in corpus: {name}")
    with as_file(resource) as corpus_path:
        return load_corpus(corpus_path)


def _safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]
