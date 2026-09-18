"""Naive Bayes content classifier. Training lives in ml/train.py; this module only serves the model."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import joblib

from app.schemas import ClassifierResult

log = logging.getLogger(__name__)

BENIGN_LABELS = frozenset({"legitimate", "legit", "ham", "safe", "benign", "normal", "0", "not phishing", "safe email"})

# Public corpora arrive pre-processed: numbers as "escapenumber…", URLs with punctuation stripped
# ("httpwwwexamplecom"). Mapping those onto the same tokens as raw mail keeps corpus formatting
# from becoming a feature.
_CORPUS_NUMBER = re.compile(r"\bescape(?:number|long)\w*", re.IGNORECASE)
_GLUED_URL = re.compile(r"\bhttps?(?:www)?[a-z0-9]{6,}\b", re.IGNORECASE)
_URL = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_MONEY = re.compile(r"(?:₹|rs\.?|inr|\$|usd|€|£)\s?\d[\d,]*(?:\.\d+)?", re.IGNORECASE)
_NUMBER = re.compile(r"\b\d+(?:[.,]\d+)*\b")
_SPACE = re.compile(r"\s+")


def normalize_text(subject: str, body: str) -> str:
    """Shared by training and inference so both see identical features."""
    text = f"{subject or ''} \n {body or ''}".lower()
    text = _URL.sub(" urltoken ", text)
    text = _GLUED_URL.sub(" urltoken ", text)
    text = _CORPUS_NUMBER.sub(" numtoken ", text)
    text = _EMAIL.sub(" emailtoken ", text)
    text = _MONEY.sub(" moneytoken ", text)
    text = _NUMBER.sub(" numtoken ", text)
    return _SPACE.sub(" ", text).strip()


class ContentClassifier:
    def __init__(self, model_path: Path) -> None:
        self._path = model_path
        self._bundle: dict | None = None
        self.load()

    def load(self) -> None:
        if not self._path.exists():
            log.info("no classifier model at %s; run ml/train.py", self._path)
            self._bundle = None
            return
        try:
            self._bundle = joblib.load(self._path)
        except Exception as exc:  # corrupted or incompatible pickle
            log.error("failed to load classifier %s: %s", self._path, exc)
            self._bundle = None

    @property
    def available(self) -> bool:
        return self._bundle is not None

    def predict(self, subject: str, body: str) -> ClassifierResult:
        if self._bundle is None:
            return ClassifierResult(available=False, reason="No trained model found. Train one with ml/train.py.")
        text = normalize_text(subject, body)
        if len(text.split()) < 3:
            return ClassifierResult(available=False, reason="Too little text to classify.")

        pipeline = self._bundle["pipeline"]
        probabilities = pipeline.predict_proba([text])[0]
        labels = [str(label) for label in pipeline.classes_]
        scores = {label: round(float(p), 4) for label, p in zip(labels, probabilities, strict=True)}
        benign = set(self._bundle.get("benign_labels") or BENIGN_LABELS)
        malicious = sum(p for label, p in scores.items() if label.lower() not in benign)
        metrics = self._bundle.get("metrics", {})
        return ClassifierResult(
            available=True,
            label=max(scores, key=scores.get),
            malicious_probability=round(malicious, 4),
            probabilities=scores,
            model={
                "variant": self._bundle.get("variant", ""),
                "trained_at": self._bundle.get("trained_at", ""),
                "macro_f1": metrics.get("macro_f1", 0.0),
                "malicious_recall": metrics.get("malicious_recall", 0.0),
            },
        )
