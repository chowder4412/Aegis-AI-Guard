from __future__ import annotations

import argparse
import csv
import hashlib
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
EXTRACTED_DIR = RAW_DIR / "extracted"


@dataclass
class SourceSummary:
    source: str
    imported_rows: int
    note: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import phishing/legitimate datasets into a training CSV")
    parser.add_argument(
        "--output",
        default=str(PROCESSED_DIR / "phishing_training_dataset.csv"),
        help="Output CSV path",
    )
    parser.add_argument(
        "--report-output",
        default=str(PROCESSED_DIR / "dataset_import_report.json"),
        help="Output JSON report path",
    )
    parser.add_argument(
        "--max-enron-rows",
        type=int,
        default=80000,
        help="Maximum number of Enron rows to import",
    )
    return parser.parse_args()


def safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in tar.getmembers():
        member_target = (destination / member.name).resolve()
        if not str(member_target).startswith(str(destination)):
            raise ValueError(f"Blocked unsafe tar path: {member.name}")
    tar.extractall(path=destination)


def extract_archive_if_needed(archive_path: Path, destination: Path) -> None:
    marker = destination / ".extracted"
    if marker.exists():
        return

    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, mode="r:*") as tar:
        safe_extract(tar, destination)
    marker.write_text("ok", encoding="utf-8")


def iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file() and path.name != ".extracted":
            yield path


def extract_message_body(path: Path) -> str:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore").replace("\r\n", "\n")
    parts = text.split("\n\n", 1)
    body = parts[1] if len(parts) == 2 else text
    body = " ".join(body.split())
    return body.strip()


def row_key(content: str, label: str) -> str:
    return hashlib.sha1(f"{label}\n{content}".encode("utf-8", errors="ignore")).hexdigest()


def append_row(
    rows: list[dict[str, str]],
    seen: set[str],
    content: str,
    label: str,
    source: str,
) -> bool:
    normalized = " ".join(content.split()).strip()
    if not normalized:
        return False
    if len(normalized) < 20:
        return False

    key = row_key(normalized, label)
    if key in seen:
        return False

    seen.add(key)
    rows.append(
        {
            "content": normalized,
            "label": label,
            "source": source,
        }
    )
    return True


def import_enron(rows: list[dict[str, str]], seen: set[str], max_rows: int) -> SourceSummary:
    csv_path = RAW_DIR / "enron" / "emails.csv"
    if csv_path.exists():
        imported = 0
        import sys
        csv.field_size_limit(min(sys.maxsize, 2147483647))
        with csv_path.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.DictReader(handle)
            for item in reader:
                msg = item.get("message", "")
                parts = msg.split("\n\n", 1)
                body = parts[1] if len(parts) == 2 else msg
                if append_row(rows, seen, body, "legitimate", "enron"):
                    imported += 1
                    if imported >= max_rows:
                        break
        return SourceSummary("enron", imported, f"imported from {csv_path.name} (max={max_rows})")

    archive = RAW_DIR / "enron_mail_20150507.tar.gz"
    if not archive.exists():
        return SourceSummary("enron", 0, f"missing archive: {archive.name} and csv: {csv_path.name}")

    destination = EXTRACTED_DIR / "enron_mail_20150507"
    extract_archive_if_needed(archive, destination)

    imported = 0
    for file_path in iter_files(destination):
        body = extract_message_body(file_path)
        if append_row(rows, seen, body, "legitimate", "enron"):
            imported += 1
            if imported >= max_rows:
                break

    note = f"imported up to max-enron-rows={max_rows}"
    return SourceSummary("enron", imported, note)


def import_spamassassin(rows: list[dict[str, str]], seen: set[str]) -> SourceSummary:
    csv_paths = [
        RAW_DIR / "spamassassin" / "spam_assassin.csv",
        RAW_DIR / "spam_assassin" / "spam_assassin.csv",
        RAW_DIR / "spam_assassin.csv",
    ]
    for csv_path in csv_paths:
        if csv_path.exists():
            imported = 0
            import sys
            csv.field_size_limit(min(sys.maxsize, 2147483647))
            with csv_path.open("r", encoding="utf-8", errors="ignore") as handle:
                reader = csv.DictReader(handle)
                for item in reader:
                    text = item.get("text", "")
                    target = str(item.get("target", "0")).strip()
                    label = "phishing" if target in {"1", "spam", "phishing"} else "legitimate"
                    if append_row(rows, seen, text, label, "spamassassin"):
                        imported += 1
            return SourceSummary("spamassassin", imported, f"imported {imported} rows from {csv_path.name}")

    archives = [
        "20021010_easy_ham.tar.bz2",
        "20021010_hard_ham.tar.bz2",
        "20021010_spam.tar.bz2",
        "20030228_easy_ham.tar.bz2",
        "20030228_easy_ham_2.tar.bz2",
        "20030228_hard_ham.tar.bz2",
        "20030228_spam.tar.bz2",
        "20030228_spam_2.tar.bz2",
        "20050311_spam_2.tar.bz2",
    ]

    imported = 0
    missing: list[str] = []
    for archive_name in archives:
        archive = RAW_DIR / archive_name
        if not archive.exists():
            missing.append(archive_name)
            continue

        destination = EXTRACTED_DIR / archive_name.replace(".tar.bz2", "")
        extract_archive_if_needed(archive, destination)

        label = "phishing" if "spam" in archive_name else "legitimate"
        for file_path in iter_files(destination):
            body = extract_message_body(file_path)
            if append_row(rows, seen, body, label, "spamassassin"):
                imported += 1

    note = "all archives imported" if not missing else f"missing {len(missing)} archives"
    return SourceSummary("spamassassin", imported, note)


def import_huggingface(rows: list[dict[str, str]], seen: set[str]) -> SourceSummary:
    jsonl_path = RAW_DIR / "hf_phishing_benign_dataset.jsonl"
    if not jsonl_path.exists():
        return SourceSummary("huggingface", 0, f"missing file: {jsonl_path.name}")

    imported = 0
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            body = str(record.get("body", "")).strip()
            subject = str(record.get("subject", "")).strip()
            content = f"{subject}\n\n{body}" if subject else body

            raw_label = str(record.get("label", "")).strip().lower()
            label = "phishing" if raw_label in {"phishing", "spam", "malicious", "1"} else "legitimate"

            if append_row(rows, seen, content, label, "huggingface"):
                imported += 1

    return SourceSummary("huggingface", imported, "jsonl imported")


def import_zenodo_reference() -> SourceSummary:
    # Record is an open paper with no downloadable email dataset rows.
    return SourceSummary("zenodo", 0, "record contains publication PDF only; no email rows available")


def import_sting9_reference() -> SourceSummary:
    # At time of import, the public dataset repo exposes license metadata only.
    return SourceSummary("sting9", 0, "public repo has no downloadable dataset rows yet")


def write_outputs(
    rows: list[dict[str, str]],
    summaries: list[SourceSummary],
    output_csv: Path,
    output_report: Path,
) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)

    with output_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["content", "label", "source"])
        writer.writeheader()
        writer.writerows(rows)

    report = {
        "total_rows": len(rows),
        "sources": [
            {
                "source": item.source,
                "imported_rows": item.imported_rows,
                "note": item.note,
            }
            for item in summaries
        ],
    }
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    summaries: list[SourceSummary] = []

    summaries.append(import_enron(rows, seen, max_rows=args.max_enron_rows))
    summaries.append(import_spamassassin(rows, seen))
    summaries.append(import_huggingface(rows, seen))
    summaries.append(import_zenodo_reference())
    summaries.append(import_sting9_reference())

    output_csv = Path(args.output)
    output_report = Path(args.report_output)
    write_outputs(rows, summaries, output_csv, output_report)

    print(f"Imported rows: {len(rows)}")
    print(f"Training CSV: {output_csv}")
    print(f"Import report: {output_report}")
    for item in summaries:
        print(f"- {item.source}: {item.imported_rows} ({item.note})")


if __name__ == "__main__":
    main()
