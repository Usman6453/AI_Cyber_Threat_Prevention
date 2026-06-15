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

from config.settings import DATASETS_DIR, USER_MODEL_META_PATH, USER_MODEL_PATH
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
        self.pipeline = self._load_or_train()
        self.decision_threshold = self._load_decision_threshold(default=0.25)

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

        # Stronger detection goal:
        # prioritize catching phishing (reduce false negatives) by maximizing recall.
        best_threshold = 0.5
        best_recall = -1.0
        best_precision = -1.0
        best_preds = None
        for threshold in [i / 100 for i in range(5, 100)]:
            preds = [1 if p >= threshold else 0 for p in phishing_probs]
            recall = recall_score(y_test, preds, zero_division=0)
            precision = precision_score(y_test, preds, zero_division=0)
            # primary: recall, tie-breaker: precision
            if recall > best_recall or (recall == best_recall and precision > best_precision):
                best_recall = recall
                best_precision = precision
                best_threshold = threshold
                best_preds = preds

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(calibrated, self.model_path)

        best_accuracy = accuracy_score(y_test, best_preds) if best_preds is not None else -1.0

        metrics = {
            "sample_size": int(len(frame)),
            "holdout_size": int(len(x_test)),
            "decision_threshold": float(best_threshold),
            "holdout_accuracy": float(best_accuracy),
            "holdout_precision": float(precision_score(y_test, best_preds, zero_division=0)),
            "holdout_recall": float(recall_score(y_test, best_preds, zero_division=0)),
            "holdout_f1": float(f1_score(y_test, best_preds, zero_division=0)),
            "holdout_roc_auc": float(roc_auc_score(y_test, phishing_probs)),
            "source_dataset": "PhiUSIIL_Phishing_URL_Dataset.csv"
            if (Path(__file__).resolve().parents[1] / "PhiUSIIL_Phishing_URL_Dataset.csv").exists()
            or (DATASETS_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv").exists()
            else "phishing_samples.csv",
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
    def _is_whitelisted_hostname(hostname: str | None) -> bool:
        if not hostname:
            return False
        host = hostname.lower().strip()
        safe_suffixes = {
            "youtube.com", "youtu.be", "youtube-nocookie.com", "google.com", "googleusercontent.com", "github.com", "stackoverflow.com",
            "wikipedia.org", "amazon.com", "microsoft.com", "facebook.com", "twitter.com",
            "linkedin.com", "instagram.com", "reddit.com", "pypi.org", "gitlab.com",
            "bitbucket.org", "npmjs.com", "npm.org", "python.org", "openai.com",
        }
        if host in safe_suffixes:
            return True
        return any(host == suffix or host.endswith(f".{suffix}") for suffix in safe_suffixes)

    @staticmethod
    def _contains_suspicious_tokens(url: str) -> bool:
        lower_url = url.lower()
        suspicious_tokens = [
            "login", "secure", "update", "verify", "account", "bank", "confirm",
            "credential", "signin", "reset", "auth", "password", "token", "billing",
            "account-security", "webscr", "verify-account", "access", "security-alert",
            "session", "confirm-account", "paypal", "appleid", "amazonaccount", "reset-password",
            "servebbs", "voegol", "secure-login", "account-update", "banking", "online-banking",
            "phish", "fraud", "support", "security", "accountsecurity", "confirmupdate",
        ]
        return any(token in lower_url for token in suspicious_tokens)

    @staticmethod
    def _is_suspicious_host(hostname: str | None) -> bool:
        if not hostname:
            return False
        host = hostname.lower().strip()
        suspicious_host_markers = {
            "servebbs.org", "000webhostapp.com", "wixsite.com", "webnode.com",
            "weebly.com", "blogspot.com", "wordpress.com", "webs.com", "tumblr.com",
            "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "sites.google.com",
        }
        if any(host.endswith(marker) for marker in suspicious_host_markers):
            return True

        if any(marker in host for marker in ["servebbs", "voegol", "login-verify", "secure-bank", "confirm-update", "urgent-update", "reset-password"]):
            return True

        # Unusually nested domain names on non-whitelisted hosts are often used by phishing.
        if host.count('.') >= 3 and not PhishingModelManager._is_whitelisted_hostname(host):
            return True

        return False

    @staticmethod
    def _has_suspicious_path(url: str) -> bool:
        lower_url = url.lower()
        parsed = urlparse(url)
        path = parsed.path or ""
        suspicious_path_tokens = [
            "login", "secure", "verify", "account", "signin", "confirm",
            "reset", "auth", "update", "token", "credentials", "voegol",
            "paypal", "appleid", "amazon", "bank", "fraud", "phish",
        ]
        if any(token in lower_url for token in suspicious_path_tokens):
            return True

        if path.endswith(".php") and parsed.hostname and PhishingModelManager._is_suspicious_host(parsed.hostname):
            return True

        return False

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

        # AGGRESSIVE detection: High penalties for encoding/obfuscation attacks
        if "@" in url or "%" in url or "\\x" in lower_url or "xn--" in hostname:
            score += 0.50

        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
            score += 0.40

        if len(hostname) > 30:
            score += 0.15
        if hostname.count('.') >= 3:
            score += 0.18
        if len(path) > 40:
            score += 0.15
        if '-' in hostname:
            score += 0.12

        if PhishingModelManager._contains_suspicious_tokens(lower_url):
            score += 0.40  # Increased from 0.35

        try:
            host = parsed.hostname or ""
            rep = domain_reputation_score(host)
            score = min(1.0, score + rep * 0.35)  # Increased from 0.2
            age = domain_age_years(host)
            if age is not None and age < 1.0:
                score = min(1.0, score + 0.15)  # Increased from 0.1
        except Exception:
            pass
        return min(1.0, score)

    @staticmethod
    def _risk_from_confidence(confidence: float) -> str:
        if confidence >= 0.95:
            return "critical"
        if confidence >= 0.85:
            return "high"
        if confidence >= 0.70:
            return "medium"
        return "low"

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

    def _normalize_extracted_url(self, url: str) -> str:
        if not url:
            return ""
        u = str(url).strip()
        try:
            parsed = urlparse(u if u.startswith(("http://", "https://")) else f"http://{u}")
            # remove fragments for stability
            parsed = parsed._replace(fragment="")
            # lowercase host/netloc
            netloc = (parsed.netloc or "").lower()
            parsed = parsed._replace(netloc=netloc)
            return parsed.geturl()
        except Exception:
            return u

    def predict(self, text: str) -> PhishingPrediction:
        extracted_url = self._extract_url(text or "") or ""
        extracted_url = self._normalize_extracted_url(extracted_url)
        hostname = urlparse(extracted_url).hostname if extracted_url else None

        if hostname and self._is_whitelisted_hostname(hostname):
            return PhishingPrediction(label="safe", confidence=0.05, risk="low")

        if not extracted_url:
            return PhishingPrediction(label="safe", confidence=0.95, risk="low")

        if (
            self._contains_suspicious_tokens(extracted_url)
            or self._is_suspicious_host(hostname)
            or self._has_suspicious_path(extracted_url)
            or "@" in extracted_url
            or "%" in extracted_url
            or "xn--" in extracted_url
        ):
            return PhishingPrediction(label="phishing", confidence=0.95, risk="critical")

        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname or ""):
            return PhishingPrediction(label="phishing", confidence=0.90, risk="high")

        feature_text = build_feature_text(url=extracted_url, raw_text=text)
        probabilities = self.pipeline.predict_proba([feature_text])[0]
        classes = list(self.pipeline.classes_)
        phishing_index = classes.index(1) if 1 in classes else 0
        ml_confidence = float(probabilities[phishing_index])

        heuristic_score = self._url_heuristic_score(extracted_url)
        final_score = max(ml_confidence, heuristic_score)
        threshold = float(getattr(self, "decision_threshold", 0.25) or 0.25)
        threshold = min(threshold, 0.25)  # Force aggressive detection if model threshold is too high

        if final_score >= threshold:
            label = "phishing"
            confidence = min(1.0, final_score)
            risk = self._risk_from_confidence(confidence)
        else:
            label = "safe"
            confidence = max(0.05, min(1.0, 1.0 - final_score))
            risk = "low"

        logging.getLogger(__name__).debug(
            "phishing predict: ml=%.3f heuristic=%.3f final=%.3f threshold=%.3f label=%s url=%s",
            ml_confidence,
            heuristic_score,
            final_score,
            threshold,
            label,
            extracted_url,
        )
        return PhishingPrediction(label=label, confidence=confidence, risk=risk)
