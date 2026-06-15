from __future__ import annotations

from database.db import DatabaseManager
from utils.event_bus import AppEventBus

from .model import PhishingModelManager


class PhishingService:
    def __init__(self, database: DatabaseManager, event_bus: AppEventBus | None = None) -> None:
        self.database = database
        self.event_bus = event_bus
        self.model_manager = PhishingModelManager()

    def scan(self, text: str, source: str = "manual") -> dict[str, object]:
        prediction = self.model_manager.predict(text)
        payload: dict[str, object] = {
            "input_text": text,
            "prediction": prediction.label,
            "confidence": prediction.confidence,
            "risk": prediction.risk,
            "source": source,
        }
        self.database.log_phishing(text, prediction.label, prediction.confidence, source)
        if self.event_bus:
            self.event_bus.emit_phishing(payload)
            self.event_bus.emit_alert({
                "title": "Phishing scan result",
                "message": f"{prediction.label.title()} content | {prediction.risk.title()} risk | {(prediction.confidence * 100):.1f}%",
                "severity": "high" if prediction.label == "phishing" else "info",
                "module": "phishing",
            })
        return payload
