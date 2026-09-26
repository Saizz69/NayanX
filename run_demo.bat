@echo off
TITLE Helios Forensic Attribution Demo
echo ===============================================================================
echo     Running Helios End-to-End Forensic Attribution Demo Script
echo ===============================================================================
cd /d "%~dp0crypto-service"
python demo_seed.py
echo.
pause
