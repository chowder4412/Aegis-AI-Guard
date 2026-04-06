from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from backend.detector import extract_features, feature_vector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the Aegis phishing decision-tree detector")
    parser.add_argument("--dataset", required=True, help="Path to a CSV dataset")
    parser.add_argument("--text-column", default="content", help="CSV column containing email text")
    parser.add_argument("--label-column", default="label", help="CSV column containing labels (1/0 or phishing/legitimate)")
    parser.add_argument("--output", default="backend/models/phishing_model.pkl", help="Output model path")
    return parser.parse_args()


def normalize_label(value: object) -> int:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "phishing", "spam", "malicious"}:
            return 1
        return 0
    return int(value)


def main() -> None:
    args = parse_args()
    frame = pd.read_csv(args.dataset)

    if args.text_column not in frame.columns or args.label_column not in frame.columns:
        raise ValueError("Dataset is missing the required text or label columns")

    texts = frame[args.text_column].fillna("").astype(str).tolist()
    labels = [normalize_label(value) for value in frame[args.label_column].tolist()]

    features = [feature_vector(extract_features(text)) for text in texts]
    x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

    model = DecisionTreeClassifier(max_depth=5, random_state=42)
    model.fit(x_train, y_train)

    accuracy = model.score(x_test, y_test)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)

    print(f"Saved model to {output_path}")
    print(f"Validation accuracy: {accuracy:.4f}")


if __name__ == "__main__":
    main()
