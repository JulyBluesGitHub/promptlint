"""Optional L3 semantic classifier (MiniLM + logistic regression), torch-free.

Scores text for prompt-injection likelihood using a MiniLM ONNX encoder plus a
logistic-regression head. Inference needs only ``onnxruntime``, ``tokenizers``,
and ``numpy`` — no torch, no sklearn (install via ``prompt-lint-py[ml]``).

The model assets (``minilm.onnx`` ~90 MB, ``tokenizer.json``, and
``lr_coefficients.json``) ship separately from the wheel. Pass their directory
to the constructor, or drop them in ``promptlint/ml/assets/``.
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.request
from pathlib import Path
from typing import Any

import numpy as np

_DEFAULT_ASSETS = Path(__file__).parent / "assets"

# GitHub release hosting the model assets. Bump alongside the package version
# whenever the assets change.
DEFAULT_MODEL_RELEASE = "v0.3.0"
_ASSET_FILES = ("minilm.onnx", "tokenizer.json", "lr_coefficients.json")
_ASSET_BASE_URL = "https://github.com/JulyBluesGitHub/promptlint/releases/download/{release}/{file}"


class PromptInjectionClassifier:
    """MiniLM + logistic-regression prompt-injection scorer (no torch at inference)."""

    def __init__(self, assets_dir: str | os.PathLike[str] | None = None) -> None:
        self._assets = Path(assets_dir) if assets_dir is not None else _DEFAULT_ASSETS
        self._session: Any = None
        self._tokenizer: Any = None
        self._coef: Any = None
        self._intercept: Any = None

    def _ensure_loaded(self) -> None:
        if self._session is not None:
            return
        # Auto-fetch on first use (no-op if the assets are already present).
        self.download_assets()
        # Defer heavy imports so `promptlint.ml` stays importable without deps.
        import onnxruntime as ort
        from tokenizers import Tokenizer

        onnx_path = self._assets / "minilm.onnx"
        tok_path = self._assets / "tokenizer.json"
        coeff_path = self._assets / "lr_coefficients.json"
        missing = [p.name for p in (onnx_path, tok_path, coeff_path) if not p.is_file()]
        if missing:
            raise FileNotFoundError(
                "promptlint ML assets missing: "
                f"{', '.join(missing)} under {self._assets}. "
                "Run classifier.download_assets() or provide the files manually."
            )
        self._session = ort.InferenceSession(str(onnx_path))
        self._tokenizer = Tokenizer.from_file(str(tok_path))
        with open(coeff_path, encoding="utf-8") as f:
            lr = json.load(f)
        self._coef = np.asarray(lr["coef"], dtype=np.float32)
        self._intercept = float(lr["intercept"])

    def download_assets(
        self,
        release: str = DEFAULT_MODEL_RELEASE,
        force: bool = False,
    ) -> None:
        """Download model assets from the GitHub release, caching locally."""
        self._assets.mkdir(parents=True, exist_ok=True)
        for name in _ASSET_FILES:
            dest = self._assets / name
            if dest.is_file() and not force:
                continue
            url = _ASSET_BASE_URL.format(release=release, file=name)
            with urllib.request.urlopen(url) as resp, open(dest, "wb") as out:
                shutil.copyfileobj(resp, out)

    def score(self, text: str) -> float:
        """Return P(injection) in [0, 1] for a single text."""
        return self.score_batch([text])[0]

    def score_batch(self, texts: list[str]) -> list[float]:
        """Return P(injection) in [0, 1] for each text."""
        self._ensure_loaded()
        encodings = self._tokenizer.encode_batch(texts)
        max_len = max(len(e.ids) for e in encodings)
        ids = np.zeros((len(texts), max_len), dtype=np.int64)
        mask = np.zeros((len(texts), max_len), dtype=np.int64)
        tids = np.zeros((len(texts), max_len), dtype=np.int64)
        for i, e in enumerate(encodings):
            n = len(e.ids)
            ids[i, :n] = e.ids
            mask[i, :n] = e.attention_mask
            tids[i, :n] = e.type_ids

        last_hidden = self._session.run(
            ["last_hidden_state"],
            {"input_ids": ids, "attention_mask": mask, "token_type_ids": tids},
        )[0]
        embedding = _mean_pool_normalize(last_hidden, mask)
        logits = embedding @ self._coef + self._intercept
        probs = 1.0 / (1.0 + np.exp(-logits))
        return [float(p) for p in probs]


def _mean_pool_normalize(last_hidden: np.ndarray, attention_mask: np.ndarray) -> np.ndarray:
    """Mean-pool over token axis (masked) and L2-normalize each row."""
    mask = attention_mask[:, :, None].astype(np.float32)
    summed = (last_hidden * mask).sum(axis=1)
    counts = mask.sum(axis=1).clip(min=1e-9)
    mean = summed / counts
    norm = np.linalg.norm(mean, axis=1, keepdims=True)
    return mean / np.maximum(norm, 1e-12)
