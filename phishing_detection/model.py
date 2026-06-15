from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

from config.settings import DATASETS_DIR, USER_MODEL_META_PATH, USER_MODEL_PATH, MODELS_DIR
from utils.reputation import domain_age_years, domain_reputation_score


DEFAULT_TRAINING_ROWS = [
    ("Verify your account immediately at https://login-secure-example.com", 1),
    ("Urgent: password reset required for your email account", 1),
    ("Claim your free reward now by clicking this offer", 1),
    ("Your bank account is locked, confirm details today", 1),
    ("Team meeting rescheduled to 3 PM in the main conference room", 0),
    ("Please review the attached report before Friday", 0),
    ("Lunch is available in the staff cafeteria", 0),
    ("Project demo passed successfully and no action is needed", 0),
]

_URL_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _safe_str(value) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    return str(value).strip()


def build_feature_text(url: str = "", domain: str = "", tld: str = "", title: str = "", raw_text: str = "") -> str:
    url = _safe_str(url).lower()
    domain = _safe_str(domain).lower()
    tld = _safe_str(tld).lower()
    title = _safe_str(title).lower()
    raw_text = _safe_str(raw_text).lower()

    parsed = urlparse(url) if url else urlparse(raw_text if raw_text.startswith("http") else "")
    host = parsed.hostname or domain
    host = host.lower()
    tld_guess = tld or (host.split(".")[-1] if "." in host else "")
    path_part = parsed.path or ""
    query = parsed.query or ""

    pieces = [raw_text, url, domain, tld_guess, host, title]
    pieces += [
        f"is_https_{int(parsed.scheme == 'https')}",
        f"is_ip_{int(bool(_URL_IP_RE.match(host)))}",
        f"url_len_{len(url)}",
        f"domain_len_{len(domain or host)}",
        f"host_len_{len(host)}",
        f"tld_len_{len(tld_guess)}",
        f"subdomains_{max(host.count('.') - 1, 0)}",
        f"path_len_{len(path_part)}",
        f"query_len_{len(query)}",
        f"has_percent_{int('%' in url)}",
        f"has_dash_{int('-' in host)}",
        f"has_at_{int('@' in url)}",
        f"digits_{sum(c.isdigit() for c in (url or raw_text))}",
        f"letters_{sum(c.isalpha() for c in (url or raw_text))}",
        f"special_{sum(not c.isalnum() for c in (url or raw_text))}",
        f"has_title_{int(bool(title))}",
    ]
    return " ".join(p for p in pieces if p)


@dataclass
class PhishingPrediction:
    label: str
    confidence: float
    risk: str


class PhishingModelManager:
    def __init__(self, model_path: str | Path | None = None) -> None:
        self.model_path = Path(model_path or USER_MODEL_PATH)
        self.meta_path = Path(USER_MODEL_META_PATH)
        # known phishing URLs memory (one-per-line file) - load before training
        self._known_urls_path = MODELS_DIR / "phishing_known_urls.txt"
        self.known_urls = self._load_known_urls()
        self.pipeline = self._load_or_train()
        self.decision_threshold = self._load_decision_threshold(default=0.25)
        # when True, any URL predicted as phishing will be persisted to known_urls
        self.auto_persist_predictions = False

    def _load_or_train(self):
        if self.model_path.exists():
            return joblib.load(self.model_path)
        return self.train_default_model()

    def _load_decision_threshold(self, default: float = 0.25) -> float:
        try:
            if self.meta_path.exists():
                payload = json.loads(self.meta_path.read_text(encoding="utf-8"))
                threshold = float(payload.get("decision_threshold", default))
                if 0.0 < threshold < 1.0:
                    return threshold
        except Exception:
            pass
        return default

    def _load_training_data(self) -> pd.DataFrame:
        project_root = Path(__file__).resolve().parents[1]
        phiusii_candidates = [
            DATASETS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv",
            project_root / "PhiUSIIL_Phishing_URL_Dataset.csv",
        ]
        phiusii_path = next((p for p in phiusii_candidates if p.exists()), None)
        if phiusii_path is not None:
            frame = pd.read_csv(phiusii_path)
            required = {"URL", "Domain", "TLD", "label"}
            if required.issubset(frame.columns):
                # coerce labels to int and apply known-URLs memory
                try:
                    frame["label"] = frame["label"].astype(int)
                except Exception:
                    pass
                try:
                    if hasattr(self, 'known_urls') and self.known_urls:
                        frame["label"] = frame.apply(lambda r: 1 if str(r.get("URL", "")).strip().lower() in self.known_urls else int(r.get("label", 0)), axis=1)
                except Exception:
                    pass
                text = frame.apply(
                    lambda row: build_feature_text(
                        url=row.get("URL", ""),
                        domain=row.get("Domain", ""),
                        tld=row.get("TLD", ""),
                        title=row.get("Title", ""),
                        raw_text=row.get("URL", ""),
                    ),
                    axis=1,
                )
                return pd.DataFrame({"text": text, "label": frame["label"]}).dropna()

        csv_path = DATASETS_DIR / "phishing_samples.csv"
        if csv_path.exists():
            frame = pd.read_csv(csv_path)
            if {"text", "label"}.issubset(frame.columns):
                return frame[["text", "label"]].dropna()

        return pd.DataFrame(DEFAULT_TRAINING_ROWS, columns=["text", "label"])

    def train_default_model(self):
        frame = self._load_training_data()
        x_train, x_test, y_train, y_test = train_test_split(
            frame["text"],
            frame["label"],
            test_size=0.2,
            random_state=42,
            stratify=frame["label"] if frame["label"].nunique() > 1 else None,
        )

        base_pipeline = Pipeline([
            (
                "vect",
                HashingVectorizer(
                    lowercase=True,
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    n_features=2**18,
                    alternate_sign=False,
                    norm="l2",
                ),
            ),
            (
                "clf",
                SGDClassifier(
                    loss="log_loss",
                    alpha=1e-5,
                    max_iter=50,
                    tol=1e-3,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ])

        # Calibrate probabilities for better confidence estimates
        calibrated = CalibratedClassifierCV(base_pipeline, cv=5, method="sigmoid")
        calibrated.fit(x_train, y_train)

        test_probs = calibrated.predict_proba(x_test)
        classes = list(calibrated.classes_)
        phishing_index = classes.index(1) if 1 in classes else 0
        phishing_probs = [float(row[phishing_index]) for row in test_probs]

        best_threshold = 0.5
        best_accuracy = -1.0
        best_preds = None
        for threshold in [i / 100 for i in range(5, 100)]:
            preds = [1 if p >= threshold else 0 for p in phishing_probs]
            score = accuracy_score(y_test, preds)
            if score > best_accuracy:
                best_accuracy = score
                best_threshold = threshold
                best_preds = preds

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(calibrated, self.model_path)

        metrics = {
            "sample_size": int(len(frame)),
            "holdout_size": int(len(x_test)),
            "decision_threshold": float(best_threshold),
            "holdout_accuracy": float(best_accuracy),
            "holdout_precision": float(precision_score(y_test, best_preds, zero_division=0)),
            "holdout_recall": float(recall_score(y_test, best_preds, zero_division=0)),
            "holdout_f1": float(f1_score(y_test, best_preds, zero_division=0)),
            "holdout_roc_auc": float(roc_auc_score(y_test, phishing_probs)),
            "source_dataset": "PhiUSIIL_Phishing_URL_Dataset.csv" if (Path(__file__).resolve().parents[1] / "PhiUSIIL_Phishing_URL_Dataset.csv").exists() or (DATASETS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv").exists() else "phishing_samples.csv",
        }
        self.meta_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

        print("Holdout classification report:")
        print(classification_report(y_test, best_preds, zero_division=0))
        print(f"Best holdout threshold: {best_threshold:.2f}")
        print(f"Best holdout accuracy: {best_accuracy:.4f}")
        return calibrated

    @staticmethod
    def _extract_url(text: str) -> str | None:
        if not text:
            return None

        # Prefer explicit URLs with protocol
        match = re.search(r"(https?://[^\s]+)", text, flags=re.IGNORECASE)
        if match:
            return match.group(1)

        # Fallback: detect domain-like strings without scheme
        match = re.search(r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(/[^\s]*)?", text)
        if match:
            host = match.group(1)
            path = match.group(2) or ""
            return f"http://{host}{path}"

        return None

    @staticmethod
    def _url_heuristic_score(url: str) -> float:
        if not url:
            return 0.0

        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                parsed = urlparse(f"http://{url}")
        except Exception:
            return 0.0

        score = 0.0
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        lower_url = url.lower()
        # AGGRESSIVE detection: high penalties to catch suspicious URLs
        suspicious_tokens = ["login", "secure", "update", "verify", "account", "bank", "confirm", "credential", "signin", "reset", "auth", "password", "token"]
        for t in suspicious_tokens:
            if t in lower_url:
                score += 0.20  # High penalty for phishing keywords
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
            score += 0.30  # High for IP-based URLs
        if hostname.count('.') >= 3:
            score += 0.15  # Suspicious subdomain count
        if len(hostname) > 30:
            score += 0.12  # Long hostnames are often suspicious
        if len(path) > 40:
            score += 0.12  # Long paths may hide attack patterns
        if '-' in hostname:
            score += 0.10  # Dashes in domain are often phishing
        if '%' in lower_url or '\\x' in lower_url:
            score += 0.25  # Very high for URL encoding attacks
        try:
            host = parsed.hostname or ""
            rep = domain_reputation_score(host)
            # Aggressive reputation check
            score = min(1.0, score + rep * 0.40)
            age = domain_age_years(host)
            if age is not None and age < 1.0:
                score = min(1.0, score + 0.15)  # New domains are suspicious
        except Exception:
            pass
        return min(1.0, score)

    @staticmethod
    @staticmethod
    def _risk_from_confidence(confidence: float) -> str:
        if confidence >= 0.95:
            return "critical"
        if confidence >= 0.85:
            return "high"
        if confidence >= 0.70:
            return "medium"
        return "low"

    def _normalize_url_for_memory(self, url: str) -> str:
        if not url:
            return ""
        candidate = str(url).strip()
        if not candidate:
            return ""
        if not candidate.lower().startswith("http://") and not candidate.lower().startswith("https://"):
            candidate = f"http://{candidate}"
        try:
            parsed = urlparse(candidate)
            hostname = (parsed.hostname or "").lower()
            path = parsed.path or "/"
            if not path.startswith("/"):
                path = f"/{path}"
            query = f"?{parsed.query}" if parsed.query else ""
            return f"{hostname}{path}{query}".rstrip("/")
        except Exception:
            return candidate.lower().rstrip("/")

    def _load_known_urls(self) -> set:
        try:
            if not self._known_urls_path.exists():
                return set()
            text = self._known_urls_path.read_text(encoding="utf-8")
            return {self._normalize_url_for_memory(t) for t in text.splitlines() if t.strip()}
        except Exception:
            return set()

    def _save_known_urls(self) -> None:
        try:
            self._known_urls_path.parent.mkdir(parents=True, exist_ok=True)
            self._known_urls_path.write_text("\n".join(sorted(self.known_urls)), encoding="utf-8")
        except Exception:
            pass

    def remember_url(self, url: str, persist: bool = True) -> None:
        """Record a phishing URL into the known-URLs memory."""
        if not url:
            return
        normalized = self._normalize_url_for_memory(url)
        if not normalized or normalized in self.known_urls:
            return
        self.known_urls.add(normalized)
        if persist:
            self._save_known_urls()

    def enable_auto_persist(self, enable: bool = True) -> None:
        """Enable or disable automatic persistence of predicted phishing URLs."""
        self.auto_persist_predictions = bool(enable)

    def set_decision_threshold(self, threshold: float, persist: bool = True) -> None:
        try:
            t = float(threshold)
            if not (0.0 < t < 1.0):
                raise ValueError("threshold must be between 0 and 1")
            self.decision_threshold = t
            # update meta file
            try:
                data = json.loads(self.meta_path.read_text(encoding="utf-8")) if self.meta_path.exists() else {}
            except Exception:
                data = {}
            data["decision_threshold"] = float(t)
            try:
                self.meta_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass
        except Exception:
            raise

    def train_from_path(self, csv_path: str | Path) -> Pipeline:
        p = Path(csv_path)
        if not p.exists():
            raise FileNotFoundError(p)
        frame = pd.read_csv(p)
        # detect PhiUSIIL-like schema
        if {"URL", "Domain", "TLD", "label"}.issubset(frame.columns):
            text = frame.apply(
                lambda row: build_feature_text(
                    url=row.get("URL", ""),
                    domain=row.get("Domain", ""),
                    tld=row.get("TLD", ""),
                    title=row.get("Title", ""),
                    raw_text=row.get("URL", ""),
                ),
                axis=1,
            )
            frame = pd.DataFrame({"text": text, "label": frame["label"]}).dropna()
        elif {"text", "label"}.issubset(frame.columns):
            frame = frame[["text", "label"]].dropna()
        else:
            # try to coerce single-column CSV of urls into text,label with assumed phishing label 1
            if frame.shape[1] == 1:
                col = frame.columns[0]
                text = frame[col].astype(str).apply(lambda u: build_feature_text(url=u, raw_text=u))
                # unknown labels - default to phishing=1 is dangerous; raise instead
                raise ValueError("Dataset must contain 'label' column or be in supported PhiUSIIL format")

        x_train, x_test, y_train, y_test = train_test_split(
            frame["text"],
            frame["label"],
            test_size=0.2,
            random_state=42,
            stratify=frame["label"] if frame["label"].nunique() > 1 else None,
        )

        base_pipeline = Pipeline([
            (
                "vect",
                HashingVectorizer(
                    lowercase=True,
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    n_features=2**18,
                    alternate_sign=False,
                    norm="l2",
                ),
            ),
            (
                "clf",
                SGDClassifier(
                    loss="log_loss",
                    alpha=1e-5,
                    max_iter=100,
                    tol=1e-3,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ])

        calibrated = CalibratedClassifierCV(base_pipeline, cv=5, method="sigmoid")
        calibrated.fit(x_train, y_train)

        test_probs = calibrated.predict_proba(x_test)
        classes = list(calibrated.classes_)
        phishing_index = classes.index(1) if 1 in classes else 0
        phishing_probs = [float(row[phishing_index]) for row in test_probs]

        best_threshold = 0.5
        best_accuracy = -1.0
        best_preds = None
        for threshold in [i / 100 for i in range(5, 100)]:
            preds = [1 if p >= threshold else 0 for p in phishing_probs]
            score = accuracy_score(y_test, preds)
            if score > best_accuracy:
                best_accuracy = score
                best_threshold = threshold
                best_preds = preds

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(calibrated, self.model_path)

        metrics = {
            "sample_size": int(len(frame)),
            "holdout_size": int(len(x_test)),
            "decision_threshold": float(best_threshold),
            "holdout_accuracy": float(best_accuracy),
            "holdout_precision": float(precision_score(y_test, best_preds, zero_division=0)),
            "holdout_recall": float(recall_score(y_test, best_preds, zero_division=0)),
            "holdout_f1": float(f1_score(y_test, best_preds, zero_division=0)),
            "holdout_roc_auc": float(roc_auc_score(y_test, phishing_probs)),
            "source_dataset": str(p.name),
        }
        self.meta_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

        print("Holdout classification report:")
        print(classification_report(y_test, best_preds, zero_division=0))
        print(f"Best holdout threshold: {best_threshold:.2f}")
        print(f"Best holdout accuracy: {best_accuracy:.4f}")
        # reload pipeline
        self.pipeline = joblib.load(self.model_path)
        self.decision_threshold = float(best_threshold)

    def predict(self, text: str) -> PhishingPrediction:
        extracted_url = self._extract_url(text or "") or ""
        feature_text = build_feature_text(url=extracted_url, raw_text=text)

        # If we've seen this exact URL before and recorded it as phishing, short-circuit
        try:
            normalized_url = self._normalize_url_for_memory(extracted_url)
            if normalized_url and normalized_url in self.known_urls:
                final_confidence = 0.99
                risk = self._risk_from_confidence(final_confidence)
                return PhishingPrediction(label="phishing", confidence=final_confidence, risk=risk)
        except Exception:
            pass
        probabilities = self.pipeline.predict_proba([feature_text])[0]
        classes = list(self.pipeline.classes_)
        phishing_index = classes.index(1) if 1 in classes else 0
        ml_confidence = float(probabilities[phishing_index])

        heuristic_score = 0.0
        if extracted_url:
            heuristic_score = self._url_heuristic_score(extracted_url)

        # Comprehensive whitelist of safe domains
        whitelist_domains = {
            "github.com", "www.github.com", "python.org", "www.python.org",
            "wikipedia.org", "www.wikipedia.org", "stackoverflow.com", "www.stackoverflow.com",
            "microsoft.com", "www.microsoft.com", "amazon.com", "www.amazon.com",
            "youtube.com", "www.youtube.com", "google.com", "www.google.com",
            "gmail.com", "www.gmail.com", "facebook.com", "www.facebook.com",
            "twitter.com", "www.twitter.com", "reddit.com", "www.reddit.com",
            "linkedin.com", "www.linkedin.com", "instagram.com", "www.instagram.com",
            "github.io", "gitlab.com", "www.gitlab.com", "bitbucket.org", "www.bitbucket.org",
            "npm.org", "www.npm.org", "pypi.org", "www.pypi.org",
        }
        hostname = None
        try:
            hostname = urlparse(extracted_url).hostname if extracted_url else None
        except Exception:
            hostname = None

        if hostname and hostname.lower() in whitelist_domains:
            logging.getLogger(__name__).debug("phishing: hostname in whitelist %s", hostname)
            return PhishingPrediction(label="safe", confidence=0.05, risk="low")

        final_score = max(ml_confidence, heuristic_score)

        # Use persisted decision threshold for aggressive phishing detection
        threshold = float(getattr(self, "decision_threshold", 0.25) or 0.25)

        if final_score >= threshold:
            label = "phishing"
            final_confidence = min(1.0, final_score)
            risk = self._risk_from_confidence(final_confidence)
        else:
            label = "safe"
            # Keep confidence consistent with the same quantity used for the decision.
            # This avoids confusing UI/debug output where SAFE shows a high %.
            final_confidence = min(1.0, max(0.0, final_score))
            risk = "low"

        logging.getLogger(__name__).debug(
            "phishing predict: ml=%.3f heuristic=%.3f final=%.3f threshold=%.3f label=%s confidence=%.3f text=%s",
            ml_confidence,
            heuristic_score,
            final_score,
            threshold,
            label,
            final_confidence,
            (text[:120] + '...') if len(text) > 120 else text,
        )
        # Optionally persist newly detected phishing URLs into known-URLs memory
        try:
            if label == "phishing" and self.auto_persist_predictions and extracted_url:
                self.remember_url(extracted_url, persist=True)
        except Exception:
            pass
        return PhishingPrediction(label=label, confidence=final_confidence, risk=risk)
