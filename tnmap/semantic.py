"""Semantic retrieval + cross-encoder reranking.

Primary retriever: sentence-transformers/all-MiniLM-L6-v2 (384-dim, ~90MB).
Reranker:         cross-encoder/ms-marco-MiniLM-L-6-v2 (~90MB).

Pickling strategy: we persist only the recipes and their embeddings.
The sentence-transformer models themselves are re-loaded from the HF cache
on each process start (fast because the weights are memory-mapped).

If sentence-transformers is unavailable (offline / install failure),
`SemanticIntent.build` returns None and the caller falls back to TF-IDF.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from .corpus import Recipe

ENCODER_ID = "sentence-transformers/all-MiniLM-L6-v2"
RERANKER_ID = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# Go fully offline if the HF cache already has the models. This skips the
# network round-trip that HuggingFace does at load-time to check for newer
# revisions, cutting cold-load time roughly in half on Windows.
_HF_CACHE = Path(os.environ.get("HF_HOME",
                                Path.home() / ".cache" / "huggingface" / "hub"))
if _HF_CACHE.exists():
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)


@dataclass
class SemanticHit:
    recipe: "Recipe"
    score: float


class SemanticIntent:
    """Dense-vector retrieval with optional cross-encoder rerank."""

    def __init__(self, recipes: list["Recipe"], embeddings: np.ndarray) -> None:
        self.recipes = recipes
        self.embeddings = embeddings.astype(np.float32)
        self._encoder = None
        self._reranker = None

    # --- model loading (lazy, cached by process) ---

    def _ensure_encoder(self):
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer
            # local_files_only avoids HF hub HEAD requests when the model is
            # already cached - the main cold-load latency win
            try:
                self._encoder = SentenceTransformer(
                    ENCODER_ID, device="cpu", local_files_only=True,
                )
            except Exception:
                self._encoder = SentenceTransformer(ENCODER_ID, device="cpu")
        return self._encoder

    def warmup_encoder(self) -> None:
        """Force encoder load + one forward pass so the first real query is hot."""
        enc = self._ensure_encoder()
        enc.encode(["warmup"], normalize_embeddings=True, show_progress_bar=False)

    def _ensure_reranker(self):
        if self._reranker is None:
            try:
                from sentence_transformers import CrossEncoder
                try:
                    self._reranker = CrossEncoder(
                        RERANKER_ID, device="cpu", local_files_only=True,
                    )
                except Exception:
                    self._reranker = CrossEncoder(RERANKER_ID, device="cpu")
            except Exception:
                self._reranker = False
        return self._reranker if self._reranker is not False else None

    # --- pickle: do not serialise the torch models ---

    def __getstate__(self):
        return {"recipes": self.recipes, "embeddings": self.embeddings}

    def __setstate__(self, state):
        self.recipes = state["recipes"]
        self.embeddings = state["embeddings"].astype(np.float32)
        self._encoder = None
        self._reranker = None

    # --- inference ---

    def suggest(self, query: str, k: int = 5, rerank: bool = True,
                pool_size: int = 30) -> list[SemanticHit]:
        """Semantic top-k, deduplicated by command, optionally reranked.

        Pipeline: encode query -> cosine vs corpus -> pool_size candidates ->
        dedupe by command -> optional cross-encoder rerank -> top-k.
        """
        q = query.strip()
        if not q:
            return []
        enc = self._ensure_encoder()
        q_vec = enc.encode([q], normalize_embeddings=True, show_progress_bar=False)
        sims = (self.embeddings @ q_vec[0]).astype(np.float32)
        pool_idx = np.argsort(-sims)[:pool_size]

        seen: set[str] = set()
        candidates: list[tuple[int, float]] = []
        for i in pool_idx:
            cmd = self.recipes[i].command
            if cmd in seen:
                continue
            seen.add(cmd)
            candidates.append((int(i), float(sims[i])))

        if rerank and len(candidates) > 1:
            rer = self._ensure_reranker()
            if rer is not None:
                pairs = [(q, self.recipes[i].description) for i, _ in candidates]
                rerank_scores = rer.predict(pairs, show_progress_bar=False)
                # Blend reranker (logit) with retriever (cosine). Sigmoid the
                # cross-encoder so both are in [0,1], weight reranker 0.7.
                rs = 1.0 / (1.0 + np.exp(-np.asarray(rerank_scores)))
                blended = [(i, 0.7 * float(r) + 0.3 * s)
                           for (i, s), r in zip(candidates, rs)]
                blended.sort(key=lambda x: -x[1])
                candidates = blended

        return [SemanticHit(self.recipes[i], s) for i, s in candidates[:k]]

    # --- construction ---

    @classmethod
    def build(cls, recipes: list["Recipe"],
              progress: bool = False) -> "SemanticIntent | None":
        """Encode the whole corpus. Returns None if sentence-transformers unavailable."""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            return None
        try:
            encoder = SentenceTransformer(ENCODER_ID, device="cpu")
        except Exception:
            return None
        texts = [r.description for r in recipes]
        emb = encoder.encode(
            texts,
            normalize_embeddings=True,
            batch_size=64,
            show_progress_bar=progress,
            convert_to_numpy=True,
        ).astype(np.float32)
        inst = cls(recipes, emb)
        inst._encoder = encoder
        return inst
