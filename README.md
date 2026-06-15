# AI-Driven Cyber Threat Prevention System

A Windows desktop cybersecurity dashboard built with PyQt6, SQLite, and scikit-learn. The project includes a premium dark UI, a standalone phishing scanner, background threat monitoring, protection actions, analytics, reporting, and packaging support for a single-file Windows executable.

## Features

- Secure login and sign-up with hashed passwords
- AI phishing detection for URLs, emails, and messages
- Real-time system monitoring with live anomaly scoring
- Emergency response actions and quarantine simulation
- SQLite-backed logs for auth, phishing, threats, devices, and protection events
- Cyber-themed dashboard with animated-style widgets and live charts
- Standalone phishing module that shares the same backend services
- Windows startup toggle and system tray support
- CSV report export and PyInstaller build script

## Project Structure

- `main.py` - main application entry point
- `phishing_detection/app.py` - standalone phishing scanner entry point
- `build_exe.py` - PyInstaller packaging helper
- `installer_script.iss` - Inno Setup installer script
- `launch_all.bat` - install dependencies and launch the app
- `assets/` - icons, themes, images, and sounds
- `database/` - SQLite database files
- `models/` - trained ML artifacts
- `reports/` - exported reports
- `gui/` - UI widgets and windows
- `monitoring/` - live system monitoring
- `protection/` - automated response actions
- `phishing_detection/` - phishing model and scanner
- `authentication/` - login and signup logic
- `analytics/` - summary calculations
- `config/` - app paths and settings
- `utils/` - event bus, logging, startup, and system helpers

## Run in Development

1. Open the project folder.
2. Double-click `launch_all.bat`.
3. The script installs the required packages and launches the desktop app.

## Build a Single EXE

1. Install the build dependencies.
2. Run `python build_exe.py` from the project root.
3. The executable is created in the PyInstaller `dist` folder.

## Notes

- The phishing scanner is intentionally implemented as a standalone module and also connected to the main dashboard through shared database entries, alerts, and event signals.
- The monitoring and protection layers are designed as safe, local simulations where destructive system actions are not required.
- The build script can generate a basic icon automatically if the ICO file is missing.
