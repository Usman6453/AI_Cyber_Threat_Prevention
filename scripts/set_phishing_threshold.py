from __future__ import annotations

import sys
from pathlib import Path
from phishing_detection.model import PhishingModelManager


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/set_phishing_threshold.py <threshold (0.0-1.0)>")
        return
    try:
        t = float(sys.argv[1])
    except Exception:
        print("Invalid threshold")
        return
    mgr = PhishingModelManager()
    mgr.set_decision_threshold(t)
    print(f"Set phishing decision_threshold to {t:.3f} and saved to metadata at {mgr.meta_path}")


if __name__ == '__main__':
    main()
