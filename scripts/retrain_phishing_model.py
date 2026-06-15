"""Retrain phishing model while preserving and updating known phishing URLs memory.

Usage:
    python scripts/retrain_phishing_model.py --dataset path/to/PhiUSIIL_Phishing_URL_Dataset.csv
"""
from __future__ import annotations

import argparse
import shutil
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

from config.settings import MODELS_DIR, USER_MODEL_PATH, USER_MODEL_META_PATH, DATASETS_DIR
from phishing_detection.model import PhishingModelManager


DEFAULT_MEMORY = MODELS_DIR / "phishing_known_urls.txt"


def normalise_url(u: str) -> str:
    if u is None:
        return ""
    return str(u).strip().lower()


def load_memory(path: Path) -> set:
    if not path.exists():
        return set()
    try:
        return {normalise_url(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except Exception:
        return set()


def save_memory(path: Path, urls: set) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(urls)), encoding="utf-8")


def backup_model(model_path: Path) -> None:
    if not model_path.exists():
        return
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    bak = model_path.with_suffix(model_path.suffix + f".{ts}.bak")
    try:
        shutil.copy2(model_path, bak)
        print(f"Backed up model to {bak}")
    except Exception as e:
        print("Warning: failed to back up model:", e)


def main():
    parser = argparse.ArgumentParser(description="Retrain phishing model with URL memory support")
    parser.add_argument("--dataset", "-d", help="Path to dataset CSV (PhiUSIIL format)")
    parser.add_argument("--memory-file", "-m", help="Path to phishing URL memory file", default=str(DEFAULT_MEMORY))
    parser.add_argument("--no-update-memory", action="store_true", help="Don't add new phishing URLs to memory after training")
    parser.add_argument("--backup", action="store_true", help="Backup existing model before training")
    args = parser.parse_args()

    dataset_path = Path(args.dataset) if args.dataset else None
    if dataset_path is None or not dataset_path.exists():
        # try default dataset locations used by the project
        candidates = [DATASETS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv", Path(__file__).resolve().parents[1] / "PhiUSIIL_Phishing_URL_Dataset.csv"]
        dataset_path = next((p for p in candidates if p.exists()), None)
        if dataset_path is None:
            raise SystemExit("No dataset provided and default PhiUSIIL dataset not found.")

    memory_path = Path(args.memory_file)
    memory = load_memory(memory_path)
    print(f"Loaded {len(memory)} known phishing URLs from memory")

    # Read dataset
    frame = pd.read_csv(dataset_path)
    if {"URL", "Domain", "TLD", "label"}.issubset(frame.columns):
        # Ensure label column is numeric 0/1
        frame["label"] = frame["label"].astype(int)

        # For any URL present in memory, force label=1
        def apply_memory_label(row):
            u = normalise_url(row.get("URL", ""))
            if u and u in memory:
                return 1
            return int(row.get("label", 0))

        frame["label"] = frame.apply(apply_memory_label, axis=1)

        # Add newly discovered phishing URLs from dataset to memory set
        discovered = {normalise_url(u) for u in frame.loc[frame["label"] == 1, "URL"].astype(str).values if u}
    elif {"text", "label"}.issubset(frame.columns):
        # try to extract explicit URL from text column where possible
        frame = frame[["text", "label"]].dropna()
        discovered = set()
    else:
        raise SystemExit("Dataset must be PhiUSIIL format (URL,Domain,TLD,label) or contain text,label columns")

    print(f"Dataset rows: {len(frame)} - phishing samples: {int((frame['label']==1).sum())}")

    # backup existing model
    if args.backup:
        backup_model(Path(USER_MODEL_PATH))

    # Train using the provided dataset directly (no temporary CSV)
    manager = PhishingModelManager()
    manager.train_from_path(dataset_path)

    # update memory if requested
    if not args.no_update_memory and discovered:
        before = len(memory)
        memory.update(discovered)
        save_memory(memory_path, memory)
        print(f"Updated memory: added {len(memory)-before} URLs (total {len(memory)}) to {memory_path}")

    print("Retraining complete. New model saved to", USER_MODEL_PATH)


if __name__ == "__main__":
    main()
