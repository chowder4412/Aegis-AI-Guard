from __future__ import annotations

from typing import Iterable

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from backend.detector import extract_features, feature_vector


class HybridPhishingModel:
    expects_text_input = True

    def __init__(
        self,
        *,
        max_features: int = 25000,
        ngram_range: tuple[int, int] = (1, 2),
        min_df: int = 2,
        random_state: int = 42,
    ) -> None:
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            sublinear_tf=True,
            max_features=max_features,
            ngram_range=ngram_range,
            min_df=min_df,
        )
        self.classifier = LogisticRegression(
            max_iter=2500,
            class_weight="balanced",
            solver="liblinear",
            random_state=random_state,
        )
        self.classes_: np.ndarray | None = None

    def _to_text_list(self, texts: Iterable[str]) -> list[str]:
        return [str(value or "") for value in texts]

    def _engineered_features(self, texts: list[str]) -> sparse.csr_matrix:
        rows = [feature_vector(extract_features(text)) for text in texts]
        return sparse.csr_matrix(np.asarray(rows, dtype=float))

    def _build_matrix(self, texts: list[str], *, fit: bool) -> sparse.csr_matrix:
        text_matrix = self.vectorizer.fit_transform(texts) if fit else self.vectorizer.transform(texts)
        feature_matrix = self._engineered_features(texts)
        return sparse.hstack([text_matrix, feature_matrix], format="csr")

    def fit(self, texts: Iterable[str], labels: Iterable[int]) -> "HybridPhishingModel":
        text_list = self._to_text_list(texts)
        y = np.asarray([int(value) for value in labels], dtype=int)
        x = self._build_matrix(text_list, fit=True)
        self.classifier.fit(x, y)
        self.classes_ = getattr(self.classifier, "classes_", None)
        return self

    def predict_proba(self, texts: Iterable[str]) -> np.ndarray:
        text_list = self._to_text_list(texts)
        x = self._build_matrix(text_list, fit=False)
        return self.classifier.predict_proba(x)

    def predict(self, texts: Iterable[str]) -> np.ndarray:
        text_list = self._to_text_list(texts)
        x = self._build_matrix(text_list, fit=False)
        return self.classifier.predict(x)
