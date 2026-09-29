@echo off
TITLE Helios System Launcher
echo ===============================================================================
echo     PROJECT HELIOS: Air-Gapped Forensic Document-Attribution System
echo     Post-Quantum Cryptography: NIST FIPS 203 (ML-KEM) ^& FIPS 204 (ML-DSA)
echo ===============================================================================
echo.

REM 1. Start Python Backend
echo [1/2] Launching Crypto-Service Backend (FastAPI on http://127.0.0.1:8000)...
start "Helios Backend (FastAPI)" cmd /k "cd /d ""%~dp0crypto-service"" && set PQC_VAULT_PASSPHRASE=airgap-helios-vault-2026-fips-compliant && set DEMO_MODE=true && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

REM 2. Start Next.js Frontend
echo [2/2] Launching Helios Web Dashboard (Next.js on http://localhost:3000)...
start "Helios Frontend (Next.js)" cmd /k "cd /d ""%~dp0web"" && npm.cmd run dev -- -p 3000"

echo.
echo ===============================================================================
echo  Services started in separate terminal windows!
echo.
echo   * Web Dashboard:  http://localhost:3000
echo   * Backend Docs:   http://127.0.0.1:8000/docs
echo   * Backend Status: http://127.0.0.1:8000/status
echo.
echo  To run the automated forensic demo script:
echo    cd crypto-service
echo    python demo_seed.py
echo ===============================================================================
pause
