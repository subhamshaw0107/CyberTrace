@echo off
set PYTHONIOENCODING=utf-8
echo ===================================================
echo Starting PS 26237 Attribution Console...
echo URL: http://127.0.0.1:8237
echo ===================================================
start http://127.0.0.1:8237
python ps26237.py serve
if errorlevel 1 (
    echo.
    echo An error occurred. Press any key to exit.
    pause >nul
)
