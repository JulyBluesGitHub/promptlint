"""Optional L3 semantic classifier (fine-tuned MiniLM), torch-free.

Scores a message for prompt-injection likelihood using a MiniLM fine-tuned on
(system prompt, message) pairs, so it can catch indirect attacks (riddles, word
games) that only read as malicious given the surrounding system prompt.

Inference needs only ``onnxruntime``, ``tokenizers``, and ``numpy`` — no torch,
no sklearn (install via ``prompt-lint-py[ml]``). The model assets
(``ft_minilm.onnx`` ~90 MB and ``tokenizer.json``) ship separately from the
wheel; pass their directory to the constructor, or drop them in
``promptlint/ml/assets/``.
"""

from __future__ import annotations

import os
import shutil
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

_DEFAULT_ASSETS = Path(__file__).parent / "assets"

# GitHub release hosting the model assets. Bump alongside the package version
# whenever the assets change.
DEFAULT_MODEL_RELEASE = "v0.5.0"
_ASSET_FILES = ("ft_minilm.onnx", "tokenizer.json")
_ASSET_BASE_URL = "https://github.com/JulyBluesGitHub/promptlint/releases/download/{release}/{file}"
_MAX_LENGTH = 128


class PromptInjectionClassifier:
    """Fine-tuned MiniLM prompt-injection scorer (no torch at inference).

    ``score(text)`` scores the message alone; ``score(text, system_prompt=...)``
    scores it together with the system prompt, which enables detection of
    indirect attacks that probe a secret the system prompt declares.
    """

    def __init__(self, assets_dir: str | os.PathLike[str] | None = None) -> None:
        self._assets = Path(assets_dir) if assets_dir is not None else _DEFAULT_ASSETS
        self._session: Any = None
        self._tokenizer: Any = None

    def _ensure_loaded(self) -> None:
        if self._session is not None:
            return
        # Auto-fetch on first use (no-op if the assets are already present).
        self.download_assets()
        # Defer heavy imports so `promptlint.ml` stays importable without deps.
        import onnxruntime as ort
        from tokenizers import Tokenizer

        onnx_path = self._assets / "ft_minilm.onnx"
        tok_path = self._assets / "tokenizer.json"
        missing = [p.name for p in (onnx_path, tok_path) if not p.is_file()]
        if missing:
            raise FileNotFoundError(
                "promptlint ML assets missing: "
                f"{', '.join(missing)} under {self._assets}. "
                "Run classifier.download_assets() or provide the files manually."
            )
        self._session = ort.InferenceSession(str(onnx_path))
        self._tokenizer = Tokenizer.from_file(str(tok_path))
        self._tokenizer.enable_truncation(max_length=_MAX_LENGTH)

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

    def score(self, text: str, system_prompt: str | None = None) -> float:
        """Return P(injection) in [0, 1] for a single message.

        ``system_prompt`` optionally provides the surrounding context so
        indirect attacks (probing a declared secret) can be detected.
        """
        return self.score_batch([text], [system_prompt or ""])[0]

    def score_batch(
        self,
        texts: Sequence[str],
        system_prompts: Sequence[str] | None = None,
    ) -> list[float]:
        """Return P(injection) in [0, 1] for each message.

        ``system_prompts`` (optional) aligns with ``texts``; omitted entries
        score the message alone.
        """
        self._ensure_loaded()
        if system_prompts is None:
            system_prompts = [""] * len(texts)
        encodings = [
            self._tokenizer.encode(sysp, text)
            for sysp, text in zip(system_prompts, texts, strict=False)
        ]
        max_len = max(len(e.ids) for e in encodings)
        ids = np.zeros((len(texts), max_len), dtype=np.int64)
        mask = np.zeros((len(texts), max_len), dtype=np.int64)
        tids = np.zeros((len(texts), max_len), dtype=np.int64)
        for i, e in enumerate(encodings):
            n = len(e.ids)
            ids[i, :n] = e.ids
            mask[i, :n] = e.attention_mask
            tids[i, :n] = e.type_ids

        logits = self._session.run(
            ["logits"],
            {"input_ids": ids, "attention_mask": mask, "token_type_ids": tids},
        )[0]
        # logits shape (batch, 2): class 0 = benign, class 1 = injection.
        probs = 1.0 / (1.0 + np.exp(-(logits[:, 1] - logits[:, 0])))
        return [float(p) for p in probs]
