from __future__ import annotations

import json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


class PhishingModelManager:
    def __init__(self, model_path: Path | str | None = None, datasets_dir: Path | None = None):
        self.model_path = Path(model_path) if model_path is not None else Path("models/phishing_model.joblib")
        self.meta_path = self.model_path.with_suffix('.meta.json')
        self.datasets_dir = Path(datasets_dir) if datasets_dir is not None else Path('datasets')
        self.pipeline = self._load_or_train()

    def _load_or_train(self):
        if self.model_path.exists():
            return joblib.load(self.model_path)
        return self.train_default_model()

    def _load_training_data(self) -> pd.DataFrame:
        csv_path = self.datasets_dir / "phishing_samples.csv"
        if csv_path.exists():
            frame = pd.read_csv(csv_path)
            if {"text", "label"}.issubset(frame.columns):
                return frame[["text", "label"]].dropna()
        # fallback small dataset
        rows = [
            ("Verify your account immediately at https://login-secure-example.com", 1),
            ("Urgent: password reset required for your email account", 1),
            ("Team meeting rescheduled to 3 PM in the main conference room", 0),
            ("Please review the attached report before Friday", 0),
        ]
        return pd.DataFrame(rows, columns=["text", "label"])

    def train_default_model(self):
        frame = self._load_training_data()
        x_train, x_test, y_train, y_test = train_test_split(
            frame["text"], frame["label"], test_size=0.25, random_state=42,
            stratify=frame["label"] if frame["label"].nunique() > 1 else None,
        )
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), stop_words="english")),
            ("clf", LogisticRegression(max_iter=1000)),
        ])
        pipeline.fit(x_train, y_train)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, self.model_path)
        metrics = {"sample_size": int(len(frame)), "holdout_size": int(len(x_test))}
        self.meta_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        return pipeline

    def predict_proba(self, text: str) -> float:
        probs = self.pipeline.predict_proba([text])[0]
        classes = list(self.pipeline.classes_)
        phishing_index = classes.index(1) if 1 in classes else 0
        return float(probs[phishing_index])
