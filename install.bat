@echo off
REM Crack Droid Installation Script for Windows
REM This script provides Windows compatibility for development/testing

echo Crack Droid Installation Script
echo =====================================
echo.
echo WARNING: This toolkit is designed for Linux environments.
echo This Windows script is for development and testing purposes only.
echo.
echo For production use, please install on:
echo - Kali Linux 2023.1 or later
echo - Ubuntu 20.04 LTS or later
echo.

pause

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

echo Python found. Checking version...
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"
if errorlevel 1 (
    echo ERROR: Python 3.8 or higher is required
    pause
    exit /b 1
)

echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing Python dependencies...
python -m pip install --upgrade pip
python -m pip install PyQt5 opencv-python cryptography requests psutil pycryptodome

echo.
echo Installation completed for Windows development environment.
echo.
echo NOTE: For full functionality, install on a Linux system using:
echo   ./install.sh
echo.
echo To start development:
echo   1. Activate virtual environment: venv\Scripts\activate.bat
echo   2. Run toolkit: python crackdroid.py
echo.

pause