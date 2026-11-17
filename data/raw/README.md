# Raw Training Datasets

Large raw dataset files are excluded from Git via `.gitignore` to stay within GitHub's file size limits.

After cloning or pulling this repository on another machine, manually place the raw CSV files in their respective folders:

- **Enron Corporate Email Corpus**: `data/raw/enron/emails.csv`
- **Apache SpamAssassin Public Corpus**: `data/raw/spamassassin/spam_assassin.csv`

Once added, you can either run `Aegis_AI_Guard_Model_Training.ipynb` directly or regenerate the processed dataset with:

```bash
python -m backend.scripts.import_training_datasets --max-enron-rows 5000
```
