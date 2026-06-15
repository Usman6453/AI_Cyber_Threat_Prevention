# Browser Extension Integration (quick)

Overview:
- A small browser extension reports opened URLs to a local HTTP bridge running inside the desktop app.
- The desktop bridge runs at `http://127.0.0.1:8765/report` and returns a JSON prediction.

Security:
- The bridge uses a simple shared secret header `X-Bridge-Auth` — change `BRIDGE_SECRET` in `config/settings.py` and `AUTH` in `browser_extension/background.js` before deployment.
- Only run the bridge locally and restrict it to `127.0.0.1`.

Installation:
1. Start the desktop app (or run `python api/native_bridge.py`) so the HTTP bridge is listening.
2. Load the extension in your Chromium-based browser: `chrome://extensions` → "Load unpacked" → select `browser_extension/` folder.

Notes:
- The extension uses `webNavigation` and `tabs` to auto-report URLs. It sends POST requests with `{url: '...'}` to the bridge.
- The bridge writes predictions into the app database table `phishing_logs`; the desktop UI will display them through the normal phishing logs view. If the desktop app is running, the bridge is wired to the app `AppEventBus` and will emit a `phishing_detected` event so the UI updates immediately.
