from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from backend.hybrid_model import HybridPhishingModel
from backend.train_detector import normalize_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a hybrid phishing detector (TF-IDF + engineered features)")
    parser.add_argument("--dataset", required=True, help="Path to CSV dataset")
    parser.add_argument("--text-column", default="content", help="CSV column containing email text")
    parser.add_argument("--label-column", default="label", help="CSV column containing labels")
    parser.add_argument("--output", default="backend/models/phishing_model_hybrid.pkl", help="Output model path")
    parser.add_argument(
        "--metrics-output",
        default="backend/models/phishing_model_hybrid_metrics.json",
        help="Output metrics JSON path",
    )
    return parser.parse_args()


def metrics_for_threshold(y_true: list[int], probabilities: list[float], threshold: float) -> dict[str, float | list[list[int]]]:
    predictions = [1 if value >= threshold else 0 for value in probabilities]
    return {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, predictions)),
        "phishing_precision": float(precision_score(y_true, predictions, zero_division=0)),
        "phishing_recall": float(recall_score(y_true, predictions, zero_division=0)),
        "phishing_f1": float(f1_score(y_true, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, predictions).tolist(),
    }


def select_best_threshold(y_true: list[int], probabilities: list[float]) -> dict[str, float | list[list[int]]]:
    candidates = [round(value, 2) for value in [0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6]]
    all_metrics = [metrics_for_threshold(y_true, probabilities, threshold) for threshold in candidates]
    best = max(all_metrics, key=lambda item: (item["phishing_f1"], item["phishing_recall"], item["phishing_precision"]))
    return {"best": best, "all": all_metrics}


def main() -> None:
    args = parse_args()
    frame = pd.read_csv(args.dataset)

    if args.text_column not in frame.columns or args.label_column not in frame.columns:
        raise ValueError("Dataset is missing required text or label columns")

    texts = frame[args.text_column].fillna("").astype(str).tolist()
    labels = [normalize_label(value) for value in frame[args.label_column].tolist()]

    x_train_full, x_test, y_train_full, y_test = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    x_train, x_val, y_train, y_val = train_test_split(
        x_train_full,
        y_train_full,
        test_size=0.15,
        random_state=42,
        stratify=y_train_full,
    )

    model = HybridPhishingModel()
    model.fit(x_train, y_train)

    val_probabilities = model.predict_proba(x_val)
    val_phishing_probabilities = [float(row[1]) for row in val_probabilities]
    threshold_metrics = select_best_threshold(y_val, val_phishing_probabilities)
    best = threshold_metrics["best"]

    test_probabilities = model.predict_proba(x_test)
    test_phishing_probabilities = [float(row[1]) for row in test_probabilities]
    test_at_recommended = metrics_for_threshold(y_test, test_phishing_probabilities, float(best["threshold"]))

    output_path = Path(args.output)
    metrics_path = Path(args.metrics_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output_path)

    payload = {
        "dataset": str(Path(args.dataset).resolve()),
        "train_rows": len(x_train),
        "validation_rows": len(x_val),
        "test_rows": len(x_test),
        "model": "HybridPhishingModel(LogisticRegression balanced + TF-IDF + engineered features)",
        "artifact": str(output_path.resolve()),
        "recommended_threshold": best["threshold"],
        "validation_metrics_at_recommended_threshold": best,
        "threshold_sweep_on_validation": threshold_metrics["all"],
        "test_metrics_at_recommended_threshold": test_at_recommended,
    }
    metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Saved hybrid model to {output_path}")
    print(f"Saved hybrid metrics report to {metrics_path}")
    print(
        "Recommended threshold="
        f"{best['threshold']} "
        f"val_precision={best['phishing_precision']:.4f} "
        f"val_recall={best['phishing_recall']:.4f} "
        f"val_f1={best['phishing_f1']:.4f} "
        f"test_precision={test_at_recommended['phishing_precision']:.4f} "
        f"test_recall={test_at_recommended['phishing_recall']:.4f} "
        f"test_f1={test_at_recommended['phishing_f1']:.4f}"
    )


if __name__ == "__main__":
    main()
