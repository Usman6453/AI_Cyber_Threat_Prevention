from __future__ import annotations

import sys

import os
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication
import threading

from analytics.service import AnalyticsService
from authentication.auth_service import AuthService
from config.settings import APP_NAME, DEFAULT_ICON_PATH, DEFAULT_THEME_PATH
from database.db import DatabaseManager
from gui.main_window import CyberDefenseWindow
from phishing_detection.service import PhishingService
from protection.service import ProtectionService
from utils.app_paths import initialize_workspace
from utils.event_bus import AppEventBus
from utils.logging_config import configure_logging
from api import native_bridge


def load_theme(app: QApplication) -> None:
    if DEFAULT_THEME_PATH.exists():
        app.setStyleSheet(DEFAULT_THEME_PATH.read_text(encoding="utf-8"))


def main() -> int:
    try:
        initialize_workspace()
        # Enable Qt plugin debug output (goes to stderr) to help diagnose native crashes
        os.environ.setdefault("QT_DEBUG_PLUGINS", "1")
        logger = configure_logging()
        logger.info("startup: workspace initialized, beginning app startup")
        app = QApplication(sys.argv)
        logger.info("QApplication created")
        app.setApplicationName(APP_NAME)
        logger.info('setApplicationName done')
        app.setStyle("Fusion")
        logger.info('setStyle done')
        if DEFAULT_ICON_PATH.exists():
            app.setWindowIcon(QIcon(str(DEFAULT_ICON_PATH)))
            logger.info('setWindowIcon done')
        load_theme(app)
        logger.info('theme loaded')

        logger.info('creating DatabaseManager')
        database = DatabaseManager()
        logger.info('DatabaseManager created')
        logger.info('creating AppEventBus')
        event_bus = AppEventBus()
        logger.info('AppEventBus created')
        logger.info('creating AuthService')
        auth_service = AuthService(database)
        logger.info('AuthService created')
        auth_service.ensure_admin()
        logger.info('ensure_admin completed')
        logger.info('creating PhishingService')
        phishing_service = PhishingService(database, event_bus)
        logger.info('PhishingService created')
        logger.info('creating ProtectionService')
        protection_service = ProtectionService(database, event_bus)
        logger.info('ProtectionService created')
        logger.info('creating AnalyticsService')
        analytics_service = AnalyticsService(database)
        logger.info('AnalyticsService created')
        logger.info('creating CyberDefenseWindow')
        window = CyberDefenseWindow(database, event_bus, auth_service, phishing_service, protection_service, analytics_service)
        logger.info('CyberDefenseWindow created')
        # Start local HTTP bridge for browser extension reporting in a daemon thread
        try:
            if getattr(native_bridge, "BRIDGE_ENABLED", True):
                # provide the app's event bus so the bridge can emit immediate UI events
                try:
                    native_bridge.set_event_bus(event_bus)
                except Exception:
                    logger.exception("failed to attach event bus to native bridge")

                bridge_thread = threading.Thread(
                    target=native_bridge.run_server,
                    kwargs={"port": native_bridge.BRIDGE_PORT, "secret": native_bridge.BRIDGE_SECRET},
                    daemon=True,
                )
                bridge_thread.start()
                logger.info(f"native bridge started on port {native_bridge.BRIDGE_PORT}")
        except Exception:
            logger.exception("failed to start native bridge")
        logger.info('showing window')
        window.show()
        logger.info('window.show() called, entering event loop')
        exit_code = app.exec()
        logger.info(f'app.exec() returned with code {exit_code}')
        return exit_code
    except Exception as e:
        import traceback
        print(f"FATAL ERROR in main: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        sys.stderr.flush()
        raise


if __name__ == "__main__":
    try:
        exit_code = main()
        raise SystemExit(exit_code)
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        sys.stderr.flush()
        raise SystemExit(1)
