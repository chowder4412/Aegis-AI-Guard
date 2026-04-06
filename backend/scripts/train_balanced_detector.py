from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from backend.train_detector import normalize_label
from backend.detector import extract_features, feature_vector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train baseline and balanced phishing detector models")
    parser.add_argument("--dataset", required=True, help="Path to a CSV dataset")
    parser.add_argument("--text-column", default="content", help="CSV column containing email text")
    parser.add_argument("--label-column", default="label", help="CSV column containing labels")
    parser.add_argument("--baseline-output", default="backend/models/phishing_model.pkl", help="Baseline model output path")
    parser.add_argument(
        "--balanced-output",
        default="backend/models/phishing_model_balanced.pkl",
        help="Balanced model output path",
    )
    parser.add_argument(
        "--metrics-output",
        default="backend/models/phishing_model_comparison.json",
        help="Metrics JSON output path",
    )
    return parser.parse_args()


def evaluate_model(model: DecisionTreeClassifier, x_test: list[list[float]], y_test: list[int]) -> dict[str, float | list[list[int]]]:
    predictions = model.predict(x_test)
    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "phishing_precision": float(precision_score(y_test, predictions, zero_division=0)),
        "phishing_recall": float(recall_score(y_test, predictions, zero_division=0)),
        "phishing_f1": float(f1_score(y_test, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
    }


def main() -> None:
    args = parse_args()
    frame = pd.read_csv(args.dataset)

    if args.text_column not in frame.columns or args.label_column not in frame.columns:
        raise ValueError("Dataset is missing the required text or label columns")

    texts = frame[args.text_column].fillna("").astype(str).tolist()
    labels = [normalize_label(value) for value in frame[args.label_column].tolist()]
    features = [feature_vector(extract_features(text)) for text in texts]

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    baseline = DecisionTreeClassifier(max_depth=5, random_state=42)
    baseline.fit(x_train, y_train)

    balanced = DecisionTreeClassifier(
        max_depth=10,
        min_samples_leaf=2,
        class_weight={0: 1.0, 1: 2.0},
        random_state=42,
    )
    balanced.fit(x_train, y_train)

    baseline_output = Path(args.baseline_output)
    balanced_output = Path(args.balanced_output)
    metrics_output = Path(args.metrics_output)
    baseline_output.parent.mkdir(parents=True, exist_ok=True)
    balanced_output.parent.mkdir(parents=True, exist_ok=True)
    metrics_output.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(baseline, baseline_output)
    joblib.dump(balanced, balanced_output)

    metrics = {
        "dataset": str(Path(args.dataset).resolve()),
        "train_rows": len(x_train),
        "test_rows": len(x_test),
        "models": {
            "baseline": {
                "params": {"max_depth": 5, "random_state": 42},
                "metrics": evaluate_model(baseline, x_test, y_test),
                "artifact": str(baseline_output.resolve()),
            },
            "balanced": {
                "params": {
                    "max_depth": 10,
                    "min_samples_leaf": 2,
                    "class_weight": {"0": 1.0, "1": 2.0},
                    "random_state": 42,
                },
                "metrics": evaluate_model(balanced, x_test, y_test),
                "artifact": str(balanced_output.resolve()),
            },
        },
    }
    metrics_output.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    baseline_f1 = metrics["models"]["baseline"]["metrics"]["phishing_f1"]
    balanced_f1 = metrics["models"]["balanced"]["metrics"]["phishing_f1"]
    print(f"Saved baseline model to {baseline_output}")
    print(f"Saved balanced model to {balanced_output}")
    print(f"Saved metrics report to {metrics_output}")
    print(f"Phishing F1 baseline: {baseline_f1:.4f}")
    print(f"Phishing F1 balanced: {balanced_f1:.4f}")


if __name__ == "__main__":
    main()
