from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from backend.detector import ModelNotReadyError, PhishingDetector


class VectorModel:
    classes_ = np.asarray([0, 1])

    def predict_proba(self, vector: np.ndarray) -> np.ndarray:
        assert isinstance(vector, np.ndarray)
        return np.asarray([[0.1, 0.9]])


class TextModel:
    expects_text_input = True
    classes_ = np.asarray([0, 1])

    def predict_proba(self, values: list[str]) -> np.ndarray:
        assert isinstance(values, list)
        assert isinstance(values[0], str)
        return np.asarray([[0.8, 0.2]])


class ReversedClassOrderModel:
    classes_ = np.asarray([1, 0])

    def predict_proba(self, _: np.ndarray) -> np.ndarray:
        return np.asarray([[0.9, 0.1]])


def test_vector_model_prediction_path() -> None:
    detector = PhishingDetector(Path("missing-model.pkl"), decision_threshold=0.5)
    detector.model = VectorModel()
    detector.model_name = "vectormodel"

    result = detector.predict("URGENT! verify your account at http://1.2.3.4")
    assert result.label == "phishing"
    assert result.phishing_probability == 0.9
    assert result.confidence == 0.9


def test_text_model_prediction_path() -> None:
    detector = PhishingDetector(Path("missing-model.pkl"), decision_threshold=0.5)
    detector.model = TextModel()
    detector.model_name = "textmodel"

    result = detector.predict("Normal project update and meeting notes.")
    assert result.label == "legitimate"
    assert result.phishing_probability == 0.2
    assert result.confidence == 0.8


def test_class_order_mapping_is_stable() -> None:
    detector = PhishingDetector(Path("missing-model.pkl"), decision_threshold=0.6)
    detector.model = ReversedClassOrderModel()
    detector.model_name = "reversed"

    result = detector.predict("test")
    assert result.label == "phishing"
    assert result.phishing_probability == 0.9


def test_predict_raises_when_model_missing() -> None:
    detector = PhishingDetector(Path("missing-model.pkl"), decision_threshold=0.5)
    detector.model = None

    with pytest.raises(ModelNotReadyError):
        detector.predict("anything")
