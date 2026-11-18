from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier


REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "data" / "raw"
MODELS_DIR = REPO_ROOT / "backend" / "models"


DATASET_SPECS = [
    {
        "key": "lawal",
        "name": "Lawal Modern Phishing ML Dataset",
        "path": RAW_DIR / "lawal" / "Modern_Phishing_Detection_ML_Dataset.xlsx",
        "sheet": "Phishing_ML_Dataset",
        "id_col": "email_id",
        "binary_col": "is_phishing",
        "multi_col": "attack_vector_category",
    },
    {
        "key": "supabros",
        "name": "Supabros Phishing Telemetry Dataset v2",
        "path": RAW_DIR / "supabros" / "supabros.xlsx",
        "sheet": "Supabros_Phishing_Dataset",
        "id_col": "email_id",
        "binary_col": "is_phishing",
        "multi_col": "attack_vector_category",
    },
    {
        "key": "supamustea",
        "name": "Supamustea Advanced Phish Detecter Corpus",
        "path": RAW_DIR / "supabros" / "supamustea.xlsx",
        "sheet": "supamustea",
        "id_col": "record_id",
        "binary_col": "is_phishing",
        "multi_col": "attack_vector_class",
    },
]


def read_excel_fast(path: Path, sheet_name: str) -> pd.DataFrame:
    import openpyxl

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb[sheet_name] if sheet_name in wb.sheetnames else wb[wb.sheetnames[0]]
    rows_iter = ws.iter_rows(values_only=True)
    header = list(next(rows_iter))
    data = list(rows_iter)
    wb.close()
    return pd.DataFrame(data, columns=header)


def evaluate_dataset(spec: dict[str, object]) -> dict[str, object]:
    path: Path = spec["path"]  # type: ignore[assignment]
    if not path.exists():
        return {"name": spec["name"], "status": "missing", "path": str(path)}

    df = read_excel_fast(path, str(spec["sheet"]))
    drop_cols = [str(spec["id_col"]), str(spec["binary_col"]), str(spec["multi_col"])]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y_bin = df[str(spec["binary_col"])]
    y_multi = df[str(spec["multi_col"])]

    X_train, X_test, yb_train, yb_test, ym_train, ym_test = train_test_split(
        X, y_bin, y_multi, test_size=0.20, stratify=y_multi, random_state=42
    )

    dt_bin = DecisionTreeClassifier(max_depth=12, random_state=42).fit(X_train, yb_train)
    dt_multi = DecisionTreeClassifier(max_depth=16, random_state=42).fit(X_train, ym_train)

    yb_pred = dt_bin.predict(X_test)
    ym_pred = dt_multi.predict(X_test)

    if spec["key"] == "supamustea":
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(dt_bin, MODELS_DIR / "supamustea_dt_binary.pkl")
        joblib.dump(dt_multi, MODELS_DIR / "supamustea_dt_multiclass.pkl")

    return {
        "key": spec["key"],
        "name": spec["name"],
        "path": str(path),
        "rows": int(len(df)),
        "features": int(X.shape[1]),
        "classes": int(y_multi.nunique()),
        "binary_accuracy": round(float(accuracy_score(yb_test, yb_pred)), 4),
        "binary_precision": round(float(precision_score(yb_test, yb_pred, zero_division=0)), 4),
        "binary_recall": round(float(recall_score(yb_test, yb_pred, zero_division=0)), 4),
        "binary_f1": round(float(f1_score(yb_test, yb_pred, zero_division=0)), 4),
        "multiclass_accuracy": round(float(accuracy_score(ym_test, ym_pred)), 4),
    }


def main() -> None:
    results = [evaluate_dataset(spec) for spec in DATASET_SPECS]
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = MODELS_DIR / "telemetry_model_metrics.json"
    report_path.write_text(json.dumps({"datasets": results}, indent=2), encoding="utf-8")
    print(f"Saved telemetry metrics report to {report_path}")
    for item in results:
        if item.get("status") == "missing":
            print(f"- {item['name']}: MISSING ({item['path']})")
        else:
            print(
                f"- {item['name']}: {item['rows']:,} rows, {item['features']} features, "
                f"Binary Acc={item['binary_accuracy']:.4%}, Multi-Class Acc={item['multiclass_accuracy']:.4%}"
            )


if __name__ == "__main__":
    main()
