from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw

from config.settings import APP_NAME, ASSETS_DIR, DEFAULT_ICON_PATH, BASE_DIR


PROJECT_ROOT = BASE_DIR
ICON_PATH = PROJECT_ROOT / "assets" / "icons" / "app_icon.ico"


def ensure_icon() -> Path:
    if ICON_PATH.exists():
        return ICON_PATH
    ICON_PATH.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGBA", (256, 256), (7, 18, 40, 255))
    draw = ImageDraw.Draw(image)
    draw.ellipse((28, 28, 228, 228), outline=(0, 229, 255, 255), width=14)
    draw.ellipse((80, 80, 176, 176), fill=(0, 255, 149, 255))
    draw.polygon([(128, 52), (188, 90), (188, 158), (128, 206), (68, 158), (68, 90)], outline=(0, 229, 255, 255))
    image.save(ICON_PATH)
    return ICON_PATH


def build() -> None:
    ensure_icon()
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        f"--name={APP_NAME.replace(' ', '_')}",
        f"--icon={ICON_PATH}",
        "--add-data=gui/theme.qss;gui",
        "--add-data=assets/icons/app_icon.svg;assets/icons",
        "--add-data=datasets/phishing_samples.csv;datasets",
        "main.py",
    ]
    subprocess.check_call(command, cwd=str(PROJECT_ROOT))


if __name__ == "__main__":
    build()
