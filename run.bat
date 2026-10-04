@echo off
set PYTHONIOENCODING=utf-8
echo ===================================================
echo Starting Cypher Trace Attribution Console...
echo URL: http://127.0.0.1:8237
echo ===================================================
start http://127.0.0.1:8237
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe ps26237.py serve
) else (
    python ps26237.py serve
)
if errorlevel 1 (
    echo.
    echo An error occurred. Press any key to exit.
    pause >nul
)
