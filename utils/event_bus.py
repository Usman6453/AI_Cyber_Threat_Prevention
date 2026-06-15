from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal


class AppEventBus(QObject):
    alert = pyqtSignal(object)
    log = pyqtSignal(object)
    threat_detected = pyqtSignal(object)
    phishing_detected = pyqtSignal(object)
    auth_event = pyqtSignal(object)
    metrics_updated = pyqtSignal(object)

    def emit_alert(self, payload: dict[str, object]) -> None:
        self.alert.emit(payload)

    def emit_log(self, payload: dict[str, object]) -> None:
        self.log.emit(payload)

    def emit_threat(self, payload: dict[str, object]) -> None:
        self.threat_detected.emit(payload)

    def emit_phishing(self, payload: dict[str, object]) -> None:
        self.phishing_detected.emit(payload)

    def emit_auth(self, payload: dict[str, object]) -> None:
        self.auth_event.emit(payload)

    def emit_metrics(self, payload: dict[str, object]) -> None:
        self.metrics_updated.emit(payload)
