from __future__ import annotations

import argparse
from pathlib import Path
from statistics import mean

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from phishing_detection.model import PhishingModelManager
from config.settings import DATASETS_DIR


def load_dataset(dataset_path: Path | None = None, sample_size: int | None = None) -> pd.DataFrame:
    if dataset_path is None:
        dataset_path = Path(__file__).resolve().parents[1] / "PhiUSIIL_Phishing_URL_Dataset.csv"
        if not dataset_path.exists():
            dataset_path = DATASETS_DIR / "phishing_samples.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(dataset_path)

    df = pd.read_csv(dataset_path)
    if {"URL", "Domain", "TLD", "label"}.issubset(df.columns):
        df = df[["URL", "label"]].rename(columns={"URL": "text"})
    elif {"text", "label"}.issubset(df.columns):
        df = df[["text", "label"]]
    else:
        raise ValueError("Dataset must contain either PhiUSIIL or text,label columns")

    df = df.dropna(subset=["text", "label"])
    if sample_size is not None and sample_size > 0 and sample_size < len(df):
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
    return df


def evaluate(manager: PhishingModelManager, df: pd.DataFrame) -> dict:
    y_true = []
    y_pred = []
    confidences = []
    results = []

    for _, row in df.iterrows():
        text = str(row["text"])
        label = int(row["label"])
        pred = manager.predict(text)
        y_true.append(label)
        y_pred.append(1 if pred.label == "phishing" else 0)
        confidences.append(pred.confidence)
        results.append({"text": text, "label": label, "predicted": pred.label, "confidence": pred.confidence, "risk": pred.risk})

    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, confidences) if len(set(y_true)) > 1 else 0.0,
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "average_confidence_phishing": mean([c for p, c in zip(y_pred, confidences) if p == 1]) if any(p == 1 for p in y_pred) else 0.0,
        "average_confidence_safe": mean([c for p, c in zip(y_pred, confidences) if p == 0]) if any(p == 0 for p in y_pred) else 0.0,
    }
    return metrics, results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a phishing smoke test for the detection model")
    parser.add_argument("--dataset", "-d", help="Path to a phishing dataset CSV file")
    parser.add_argument("--sample", "-s", type=int, default=2000, help="Number of rows to evaluate (default: 2000)")
    parser.add_argument("--threshold", "-t", type=float, help="Set a live decision threshold before evaluation")
    parser.add_argument("--show-samples", action="store_true", help="Show the top 10 misclassified examples")
    args = parser.parse_args()

    manager = PhishingModelManager()
    if args.threshold is not None:
        manager.set_decision_threshold(args.threshold)

    dataset_path = Path(args.dataset) if args.dataset else None
    df = load_dataset(dataset_path, sample_size=args.sample)

    print(f"Using dataset: {dataset_path or 'auto-detected'}")
    print(f"Rows evaluated: {len(df)}")
    print(f"Current decision threshold: {manager.decision_threshold:.3f}")

    metrics, results = evaluate(manager, df)

    print("\n=== Phishing Smoke Test Results ===")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1:        {metrics['f1']:.4f}")
    print(f"ROC AUC:   {metrics['roc_auc']:.4f}")
    print(f"Confusion matrix [TN, FP, FN, TP]: {metrics['confusion_matrix']}")
    print(f"Avg phishing confidence: {metrics['average_confidence_phishing']:.3f}")
    print(f"Avg safe confidence:     {metrics['average_confidence_safe']:.3f}")

    if args.show_samples:
        misclassified = [r for r in results if (r["label"] == 1 and r["predicted"] == 0) or (r["label"] == 0 and r["predicted"] == 1)]
        print(f"\nTop {min(10, len(misclassified))} misclassified examples:")
        for row in misclassified[:10]:
            print(f"label={row['label']} pred={row['predicted']} conf={row['confidence']:.3f} text={row['text']}")


if __name__ == "__main__":
    main()
