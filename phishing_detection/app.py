from __future__ import annotations

from PyQt6.QtWidgets import QApplication, QMainWindow

from database.db import DatabaseManager
from gui.widgets import PhishingScannerWidget
from utils.event_bus import AppEventBus
from phishing_detection.service import PhishingService


class StandalonePhishingWindow(QMainWindow):
    def __init__(self, phishing_service: PhishingService) -> None:
        super().__init__()
        self.setWindowTitle("Standalone Phishing Scanner")
        self.setCentralWidget(PhishingScannerWidget(phishing_service))
        self.resize(900, 700)


_app_instance = None
_window_instance = None


def launch_phishing_app() -> None:
    global _app_instance, _window_instance
    if QApplication.instance() is None:
        _app_instance = QApplication([])
    app = QApplication.instance()
    database = DatabaseManager()
    bus = AppEventBus()
    phishing_service = PhishingService(database, bus)
    _window_instance = StandalonePhishingWindow(phishing_service)
    _window_instance.show()
    if _app_instance is not None:
        _app_instance.exec()
