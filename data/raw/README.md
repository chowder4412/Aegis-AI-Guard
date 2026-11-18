# Raw Training Datasets

This folder organizes both legacy unstructured email corpora and modern 2026 structured telemetry datasets used by **Aegis AI Guard**.

## 1. Legacy Email Text Corpora (Excluded from Git)
Large raw email dumps are excluded via `.gitignore` to stay within GitHub's file size limits. After cloning or pulling on another PC, place them manually in:
- **Enron Corporate Email Corpus**: `data/raw/enron/emails.csv`
- **Apache SpamAssassin Public Corpus**: `data/raw/spamassassin/spam_assassin.csv`

## 2. Modern Structured Telemetry Datasets (`lawal` & `supabros`)
- **Lawal Modern Phishing ML Dataset**: `data/raw/lawal/Modern_Phishing_Detection_ML_Dataset.xlsx` (1,500 rows × 34 columns)
- **Supabros Phishing Telemetry Dataset v2**: `data/raw/supabros/supabros.xlsx` (22,500 rows × 48 columns)
- **Supabros Phish Detecter CSV Batches**: `data/raw/supabros/supabros_phish_detecter_batch_1..4.csv` (4 × 50,000 = 200,000 rows × 27 columns)
- **Supamustea Advanced Phish Detecter Corpus**: `data/raw/supabros/supamustea.xlsx` (210,000 rows × 65 columns across 16 attack vectors)

To regenerate `data/raw/supabros/supamustea.xlsx` on any machine:
```bash
python scripts/generate_supamustea.py
```

To refresh `data/processed/phishing_training_dataset.csv` and `data/processed/dataset_import_report.json`:
```bash
python -m backend.scripts.import_training_datasets --max-enron-rows 5000
```

To train and benchmark Decision Trees across all modern telemetry workbooks:
```bash
python -m backend.scripts.train_telemetry_detector
```
