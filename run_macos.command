#!/bin/zsh
cd "$(dirname "$0")"
if ! python3 -c 'import customtkinter, keyring, PIL, requests' >/dev/null 2>&1; then
  echo "Gerekli Python paketleri ilk kez kuruluyor..."
  python3 -m pip install -r requirements.txt || exit 1
fi
python3 app.py
