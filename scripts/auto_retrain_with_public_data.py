"""Aggregate public phishing feeds and retrain the phishing model.

This script attempts to download OpenPhish and URLhaus feeds, builds a labeled CSV,
and runs the existing training script to produce an improved model at models/phishing_model.joblib.

If downloads fail (no network), it will fall back to the existing local dataset.
"""
from __future__ import annotations

import csv
import io
import random
import sys
from pathlib import Path

import requests
import pandas as pd

import sys
from pathlib import Path as _P
_ROOT = _P(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from config.settings import DATASETS_DIR

OPENPHISH = "https://openphish.com/feed.txt"
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv/"


def fetch_openphish() -> list[str]:
    try:
        resp = requests.get(OPENPHISH, timeout=20)
        resp.raise_for_status()
        lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
        return lines
    except Exception as exc:
        print("OpenPhish fetch failed:", exc)
        return []


def fetch_urlhaus() -> list[str]:
    try:
        resp = requests.get(URLHAUS_CSV, timeout=30)
        resp.raise_for_status()
        text = resp.text
        reader = csv.DictReader(io.StringIO(text))
        urls = []
        for row in reader:
            url = row.get("url") or row.get("URL") or row.get("domain")
            if url:
                urls.append(url.strip())
        return urls
    except Exception as exc:
        print("URLhaus fetch failed:", exc)
        return []


def build_dataset(out_path: Path) -> int:
    phishing_urls = set()
    phishing_urls.update(fetch_openphish())
    phishing_urls.update(fetch_urlhaus())

    # Minimal benign examples to balance dataset if feeds are small
    benign_urls = [
        "https://www.microsoft.com",
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://example.com/about",
        "https://github.com/explore",
    ]

    rows = []
    for u in phishing_urls:
        rows.append({"text": f"Please visit {u}", "label": 1})

    # add benign rows from existing samples if present
    local_csv = DATASETS_DIR / "phishing_samples.csv"
    if local_csv.exists():
        try:
            df_local = pd.read_csv(local_csv)
            for _, r in df_local.iterrows():
                rows.append({"text": str(r.get("text", "")), "label": int(r.get("label", 0))})
        except Exception:
            pass

    # add synthetic benign rows
    for b in benign_urls:
        rows.append({"text": f"Visit our site {b}", "label": 0})

    # if no phishing URLs were fetched, return 0
    if not phishing_urls:
        print("No external phishing feeds fetched; aborting auto-aggregation.")
        return 0

    random.shuffle(rows)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["text", "label"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"Wrote aggregated dataset with {len(rows)} rows to {out_path}")
    return len(rows)


def main():
    out = DATASETS_DIR / "phishing_samples.csv"
    n = build_dataset(out)
    if n <= 0:
        print("Falling back to existing dataset; run scripts/train_phishing_model.py manually if needed.")
        sys.exit(1)
    # call the existing training script
    import runpy

    runpy.run_path(str(Path(__file__).with_name("train_phishing_model.py")), run_name="__main__")


if __name__ == "__main__":
    main()
