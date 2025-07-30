@echo off
setlocal
title Blockchain Application Launcher

:: ------------------------------------------------------------------
:: This script uses GOTO labels for all logic to ensure maximum
:: compatibility and avoid all complex parsing errors.
:: ------------------------------------------------------------------

echo =================================
echo "Blockchain Setup & Launch"
echo =================================
echo.

:: Step 1: Check for Python
echo [1/5] Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 GOTO PythonError
echo Python found.
echo.

:: Step 2: Check for requirements.txt
echo [2/5] Verifying 'requirements.txt' file...
if not exist "requirements.txt" GOTO RequirementsError
echo 'requirements.txt' found.
echo.

:: Step 3: Handle Virtual Environment
echo [3/5] Setting up virtual environment...
if exist "venv\Scripts\activate.bat" GOTO ActivateVenv

:CreateVenv
echo Creating new virtual environment (this may take a moment)...
python -m venv venv
:: Verify that creation was successful
if not exist "venv\Scripts\activate.bat" GOTO VenvCreationError

:ActivateVenv
call "venv\Scripts\activate.bat"
echo Virtual environment is now active.
echo.

:: Step 4: Install Packages
echo [4/5] Installing required packages...
pip install -r requirements.txt
echo.

:: Step 5: Launch the Application
echo [5/5] Starting the blockchain server...
echo.
echo =========================================================
echo  Setup complete. Starting the blockchain server now.
echo.
echo  Access the GUI at: http://127.0.0.1:5000
echo.
echo  Press CTRL+C in this window to stop the server.
echo =========================================================
echo.
python blockchain_app.py
GOTO End


:: ---------- ERROR HANDLING BLOCKS ----------

:PythonError
echo.
echo [ERROR] Python not found!
echo Please install Python 3 (from python.org) and make sure
echo you check the "Add Python to PATH" option during installation.
GOTO FinalPause

:RequirementsError
echo.
echo [ERROR] 'requirements.txt' not found in this directory.
echo Please ensure the file exists before running this script.
GOTO FinalPause

:VenvCreationError
echo.
echo [ERROR] Failed to create the virtual environment.
echo Please check your Python installation and folder permissions.
GOTO FinalPause


:: ---------- SCRIPT EXIT ----------

:FinalPause
echo.
pause

:End
endlocal