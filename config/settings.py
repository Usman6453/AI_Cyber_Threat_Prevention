from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
ASSETS_DIR = BASE_DIR / "assets"
ICONS_DIR = ASSETS_DIR / "icons"
SOUNDS_DIR = ASSETS_DIR / "sounds"
THEMES_DIR = ASSETS_DIR / "themes"
IMAGES_DIR = ASSETS_DIR / "images"
DATABASE_DIR = BASE_DIR / "database"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
MODELS_DIR = BASE_DIR / "models"
DATASETS_DIR = BASE_DIR / "datasets"
QUARANTINE_DIR = BASE_DIR / "quarantine"
BLOCKLIST_DIR = BASE_DIR / "blocklists"
MONITORED_FOLDER = BASE_DIR / "watched"
CONFIG_DIR = BASE_DIR / "config"

APP_NAME = "AI-Driven Cyber Threat Prevention System"
APP_SHORT_NAME = "CyberThreatShield"
APP_VERSION = "1.0.0"
APP_THEME = "cyber_dark"
DB_PATH = DATABASE_DIR / "cyber_threat_system.db"
USER_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
USER_MODEL_META_PATH = MODELS_DIR / "phishing_model.meta.json"
DEFAULT_ICON_PATH = ICONS_DIR / "app_icon.svg"
DEFAULT_THEME_PATH = THEMES_DIR / "cyber.qss"
BLOCKED_IPS_PATH = BLOCKLIST_DIR / "blocked_ips.txt"
LAUNCH_BATCH = BASE_DIR / "launch_all.bat"

# Local HTTP bridge settings for browser-extension integration
# Restrict to localhost and use a shared secret. Change before deployment.
BRIDGE_ENABLED = True
BRIDGE_PORT = 8765
BRIDGE_SECRET = "change_this_secret"

DIRECTORIES = [
    ASSETS_DIR,
    ICONS_DIR,
    SOUNDS_DIR,
    THEMES_DIR,
    IMAGES_DIR,
    DATABASE_DIR,
    LOGS_DIR,
    REPORTS_DIR,
    MODELS_DIR,
    DATASETS_DIR,
    QUARANTINE_DIR,
    BLOCKLIST_DIR,
    MONITORED_FOLDER,
]


def ensure_directories() -> None:
    for directory in DIRECTORIES:
        directory.mkdir(parents=True, exist_ok=True)
