from __future__ import annotations

from pathlib import Path

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None


RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


def set_startup(enabled: bool, app_name: str, app_path: str) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, app_path)
            else:
                try:
                    winreg.DeleteValue(key, app_name)
                except FileNotFoundError:
                    pass
        return True
    except OSError:
        return False
