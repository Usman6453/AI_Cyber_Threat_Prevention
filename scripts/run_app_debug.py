import traceback
import sys
from pathlib import Path

# Ensure project root on path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import main
    try:
        rc = main.main()
        print('main returned', rc)
    except Exception:
        traceback.print_exc()
except Exception:
    traceback.print_exc()
