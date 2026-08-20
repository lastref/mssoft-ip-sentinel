@echo off
setlocal
cd /d "%~dp0"
python -c "import customtkinter, keyring, PIL, requests" >nul 2>&1
if errorlevel 1 (
  echo Gerekli Python paketleri ilk kez kuruluyor...
  python -m pip install -r requirements.txt || exit /b 1
)
python app.py
endlocal
