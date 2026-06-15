@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0AI_Cyber_Threat_Prevention"

where py >nul 2>nul
if %errorlevel%==0 (
    set PY=py -3
) else (
    set PY=python
)

echo Installing required packages...
!PY! -m pip install --upgrade pip
!PY! -m pip install -r requirements.txt

echo Launching the cyber threat prevention system...
!PY! main.py
if %errorlevel% neq 0 (
    echo.
    echo ERROR: The application failed to start. Check the log above.
    pause
)
