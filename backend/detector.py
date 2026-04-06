from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
import warnings

import joblib
import numpy as np

try:
    from sklearn.exceptions import InconsistentVersionWarning
except ImportError:  # pragma: no cover
    InconsistentVersionWarning = Warning


SUSPICIOUS_WORDS = ("urgent", "verify", "login", "password", "bank", "click")

# Pre-compiled regex patterns (avoids recompilation on every call)
_URL_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)
_IP_URL_PATTERN = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", re.IGNORECASE)
_SUSPICIOUS_WORD_PATTERNS = {word: re.compile(rf"\b{word}\b") for word in SUSPICIOUS_WORDS}
_EXCLAMATION_PATTERN = re.compile(r"!")
_DIGIT_PATTERN = re.compile(r"\d")
_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


class ModelNotReadyError(RuntimeError):
    pass


def _count_matches(value: str, pattern: re.Pattern[str]) -> int:
    return len(pattern.findall(value))


def _is_phishing_class(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "phishing", "spam", "malicious"}

    try:
        return int(value) == 1
    except (TypeError, ValueError):
        return False


def extract_features(content: str) -> dict[str, Any]:
    normalized = content.lower()

    return {
        "num_links": _count_matches(content, _URL_PATTERN),
        "has_ip_url": bool(_IP_URL_PATTERN.search(content)),
        "num_suspicious_words": sum(_count_matches(normalized, _SUSPICIOUS_WORD_PATTERNS[word]) for word in SUSPICIOUS_WORDS),
        "num_exclamations": _count_matches(content, _EXCLAMATION_PATTERN),
        "email_length": len(content),
        "num_digits": _count_matches(content, _DIGIT_PATTERN),
        "has_html": bool(_HTML_TAG_PATTERN.search(content)),
    }


def feature_vector(features: dict[str, Any]) -> list[float]:
    return [
        float(features["num_links"]),
        float(int(features["has_ip_url"])),
        float(features["num_suspicious_words"]),
        float(features["num_exclamations"]),
        float(features["email_length"]),
        float(features["num_digits"]),
        float(int(features["has_html"])),
    ]


@dataclass
class DetectorResult:
    label: str
    confidence: float
    phishing_probability: float
    features: dict[str, Any]
    model_name: str


class PhishingDetector:
    def __init__(self, model_path: Path, decision_threshold: float = 0.5):
        self.model_path = model_path
        self.decision_threshold = float(decision_threshold)
        self.model = None
        self.model_name = "decision-tree"
        self.reload()

    def reload(self) -> None:
        if not self.model_path.exists():
            self.model = None
            return

        # The serialized model is pinned in requirements; keep startup quiet when a
        # developer's local interpreter has a newer scikit-learn installed.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
            loaded = joblib.load(self.model_path)
        self.model = loaded
        self.model_name = getattr(loaded, "__class__", type(loaded)).__name__.replace("Classifier", "").lower() or "decision-tree"

    @property
    def ready(self) -> bool:
        return self.model is not None

    def _candidate_inputs(self, content: str, vector: np.ndarray) -> list[Any]:
        if getattr(self.model, "expects_text_input", False):
            return [[content], vector]
        return [vector, [content]]

    def predict(self, content: str) -> DetectorResult:
        if not self.model:
            raise ModelNotReadyError(f"Model file not found or not loaded: {self.model_path}")

        features = extract_features(content)
        vector = np.asarray([feature_vector(features)], dtype=float)
        candidate_inputs = self._candidate_inputs(content, vector)

        if hasattr(self.model, "predict_proba"):
            last_error: Exception | None = None
            probabilities = None
            for candidate in candidate_inputs:
                try:
                    probabilities = self.model.predict_proba(candidate)[0]
                    break
                except Exception as exc:  # pragma: no cover - fallback for model input shape mismatch
                    last_error = exc

            if probabilities is None:
                if last_error:
                    raise last_error
                raise ModelNotReadyError("Model does not support probability inference")

            phishing_probability = None
            classes = getattr(self.model, "classes_", None)
            if classes is not None and len(classes) == len(probabilities):
                for index, class_value in enumerate(classes):
                    if _is_phishing_class(class_value):
                        phishing_probability = float(probabilities[index])
                        break

            if phishing_probability is None:
                if len(probabilities) >= 2:
                    phishing_probability = float(probabilities[-1])
                else:
                    phishing_probability = float(np.max(probabilities))
        else:
            prediction = None
            last_error = None
            for candidate in candidate_inputs:
                try:
                    prediction = self.model.predict(candidate)[0]
                    break
                except Exception as exc:  # pragma: no cover - fallback for model input shape mismatch
                    last_error = exc

            if prediction is None:
                if last_error:
                    raise last_error
                raise ModelNotReadyError("Model does not support prediction")
            phishing_probability = 1.0 if int(prediction) == 1 else 0.0

        label = "phishing" if phishing_probability >= self.decision_threshold else "legitimate"
        confidence = phishing_probability if label == "phishing" else 1.0 - phishing_probability

        return DetectorResult(
            label=label,
            confidence=confidence,
            phishing_probability=phishing_probability,
            features=features,
            model_name=self.model_name,
        )
