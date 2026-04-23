"""Two-model command suggester.

IntentModel: TF-IDF + cosine NN over recipe descriptions.
    input:  free-form English
    output: top-k matching Recipe objects, with scores

FlagBigram: simple Markov bigram over flag token sequences from the corpus.
    input:  a partial command (the flag tokens already typed)
    output: top-k next-flag candidates, with probabilities, Laplace-smoothed

Training is cheap (<100 ms). We still cache to disk so the TUI starts
instantly on second run.
"""
from __future__ import annotations

import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .corpus import RECIPES, Recipe, build_corpus, flag_tokens
from .semantic import SemanticIntent

MODEL_PATH = Path(__file__).with_name("model.pkl")

_START = "<s>"
_END = "</s>"


@dataclass
class IntentHit:
    recipe: Recipe
    score: float


@dataclass
class FlagHit:
    token: str
    prob: float


class IntentModel:
    def __init__(self, recipes: list[Recipe]) -> None:
        self.recipes = recipes
        corpus = [f"{r.description} {' '.join(r.tags)}" for r in recipes]
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
            lowercase=True,
        )
        self.matrix = self.vectorizer.fit_transform(corpus)

    def suggest(self, query: str, k: int = 5) -> list[IntentHit]:
        """Top-k hits, deduplicated by command.

        The training corpus contains many paraphrases of the same recipe;
        without dedup, one popular recipe can fill the entire top-k.
        """
        if not query.strip():
            return []
        q_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self.matrix).ravel()
        order = np.argsort(-sims)
        seen: set[str] = set()
        out: list[IntentHit] = []
        for i in order:
            s = float(sims[i])
            if s <= 0.0:
                break
            cmd = self.recipes[i].command
            if cmd in seen:
                continue
            seen.add(cmd)
            out.append(IntentHit(self.recipes[i], s))
            if len(out) >= k:
                break
        return out


class FlagBigram:
    def __init__(self, recipes: list[Recipe]) -> None:
        self.transitions: dict[str, Counter] = defaultdict(Counter)
        self.vocab: set[str] = set()
        for r in recipes:
            seq = [_START] + flag_tokens(r.command) + [_END]
            for a, b in zip(seq, seq[1:]):
                self.transitions[a][b] += 1
                self.vocab.add(b)
        self.vocab.discard(_END)
        self._vocab_size = len(self.vocab)

    def _context_key(self, tokens: list[str]) -> str:
        return tokens[-1] if tokens else _START

    def suggest(self, tokens: list[str], k: int = 6, prefix: str = "") -> list[FlagHit]:
        """Predict next flag given already-typed tokens.

        prefix filters candidates to ones starting with that string - useful
        when the user has started typing the next flag and wants completion.
        Uses add-1 Laplace smoothing so unseen-but-valid flags still appear.
        """
        key = self._context_key(tokens)
        counts = self.transitions.get(key, Counter())
        denom = sum(counts.values()) + self._vocab_size
        scored: list[FlagHit] = []
        for token in self.vocab:
            if prefix and not token.startswith(prefix):
                continue
            if token in tokens:
                # do not resuggest exact tokens already present
                continue
            p = (counts.get(token, 0) + 1) / denom
            scored.append(FlagHit(token, p))
        scored.sort(key=lambda h: -h.prob)
        return scored[:k]


@dataclass
class Suggester:
    intent: IntentModel
    flags: FlagBigram
    semantic: SemanticIntent | None = None

    def suggest_intent(self, query: str, k: int = 5) -> list[IntentHit]:
        """Primary intent lookup: semantic retriever + cross-encoder if available,
        TF-IDF otherwise. Output is uniform [IntentHit]."""
        if self.semantic is not None:
            hits = self.semantic.suggest(query, k=k, rerank=True)
            return [IntentHit(h.recipe, h.score) for h in hits]
        return self.intent.suggest(query, k=k)

    def save(self, path: Path = MODEL_PATH) -> None:
        with path.open("wb") as fh:
            pickle.dump(self, fh)

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "Suggester":
        with path.open("rb") as fh:
            return pickle.load(fh)

    @classmethod
    def train(cls, recipes: list[Recipe] | None = None,
              with_semantic: bool = True,
              progress: bool = False) -> "Suggester":
        if recipes is None:
            recipes = build_corpus()
        sem = SemanticIntent.build(recipes, progress=progress) if with_semantic else None
        return cls(intent=IntentModel(recipes), flags=FlagBigram(recipes), semantic=sem)

    @classmethod
    def load_or_train(cls, path: Path = MODEL_PATH) -> "Suggester":
        if path.exists():
            try:
                return cls.load(path)
            except Exception:
                pass
        model = cls.train()
        try:
            model.save(path)
        except Exception:
            pass
        return model


def main() -> None:
    """CLI: train and persist the model.

    Re-import via the package path so pickled classes are qualified as
    tnmap.model.* rather than __main__.* (which breaks loading).
    """
    from tnmap.corpus import build_corpus as _bc
    from tnmap.model import Suggester as _S, MODEL_PATH as _P
    recipes = _bc()
    print(f"Training intent + flags + semantic on {len(recipes)} recipes...")
    model = _S.train(recipes, with_semantic=True, progress=True)
    model.save(_P)
    sem_dim = model.semantic.embeddings.shape if model.semantic is not None else "disabled"
    print(f"Wrote -> {_P}  (semantic embeddings: {sem_dim})")


if __name__ == "__main__":
    main()
