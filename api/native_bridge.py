from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable when running this script directly
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

from flask import Flask, request, jsonify

from config.settings import ensure_directories, BRIDGE_PORT, BRIDGE_SECRET, BRIDGE_ENABLED
from database.db import DatabaseManager
from phishing_detection.model import PhishingModelManager
from utils.event_bus import AppEventBus
from datetime import datetime

# Simple local bridge that receives URL checks from a browser extension
# and runs the phishing model, storing results in the app database.

APP_PORT = int(BRIDGE_PORT)
SHARED_SECRET = BRIDGE_SECRET

app = Flask(__name__)

# initialize lightweight app resources (same as desktop app)
ensure_directories()
db = DatabaseManager()
model_mgr = PhishingModelManager()

# optional event bus provided by main application; when present we emit
# `phishing_detected` events so the UI updates immediately.
event_bus: AppEventBus | None = None

def set_event_bus(bus: AppEventBus) -> None:
    global event_bus
    event_bus = bus


@app.route("/report", methods=["POST"])
def report_url():
    # Basic auth via custom header to avoid open proxy
    auth = request.headers.get("X-Bridge-Auth", "")
    if auth != SHARED_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(force=True, silent=True) or {}
    url = payload.get("url") or payload.get("u") or ""
    source = payload.get("source", "browser_extension")

    if not url:
        return jsonify({"error": "no url provided"}), 400

    pred = model_mgr.predict(url)

    created_at = datetime.utcnow().isoformat()
    payload = {
        "input_text": url,
        "prediction": pred.label,
        "confidence": pred.confidence,
        "risk": pred.risk,
        "source": source,
        "created_at": created_at,
    }

    # emit event so UI can react immediately
    try:
        if event_bus is not None:
            event_bus.emit_phishing(payload)
            event_bus.emit_alert({
                "title": "Phishing scan result",
                "message": f"{pred.label.title()} site | {pred.risk.title()} risk | {(pred.confidence * 100):.1f}%",
                "severity": "high" if pred.label == "phishing" else "info",
                "module": "phishing",
            })
    except Exception:
        # never let event emission break the API
        pass

    # persist to DB for the desktop app to display
    try:
        db.log_phishing(url, pred.label, pred.confidence, source)
    except Exception:
        # do not fail the request if logging fails
        pass

    return jsonify({"label": pred.label, "confidence": pred.confidence, "risk": pred.risk})


def run_server(port: int = APP_PORT, secret: str | None = None) -> None:
    global SHARED_SECRET
    if secret:
        SHARED_SECRET = secret
    # bind only to localhost for safety
    app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    if not BRIDGE_ENABLED:
        print("Bridge disabled (BRIDGE_ENABLED=False) in config.settings")
    else:
        run_server()
