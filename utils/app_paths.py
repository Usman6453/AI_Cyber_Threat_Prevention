from __future__ import annotations

from pathlib import Path

from config.settings import BASE_DIR, ensure_directories


def project_root() -> Path:
    return BASE_DIR


def initialize_workspace() -> None:
    ensure_directories()
