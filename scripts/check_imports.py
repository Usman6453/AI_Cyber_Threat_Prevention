import traceback
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

modules = [
    'PyQt6',
    'analytics.service',
    'authentication.auth_service',
    'config.settings',
    'database.db',
    'gui.main_window',
    'phishing_detection.service',
    'protection.service',
    'utils.event_bus',
]

for m in modules:
    try:
        __import__(m)
        print(f'OK: {m}')
    except Exception:
        print(f'ERROR importing {m}')
        traceback.print_exc()
