from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from pathlib import Path

import keyring
from keyring.backends.fail import Keyring as FailKeyring


SERVICE_NAME = "MSSOFT IP Sentinel"
SETTINGS_PATH = Path.home() / ".mssoft-ip-sentinel" / "settings.json"
MAX_LABEL_LENGTH = 64
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


class SettingsStore:
    def __init__(self) -> None:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            SETTINGS_PATH.parent.chmod(0o700)
        except OSError:
            # Some filesystems do not support POSIX permissions (for example FAT).
            pass

    def list_keys(self) -> list[dict[str, str]]:
        if not SETTINGS_PATH.exists():
            return []
        try:
            payload = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        entries = payload.get("api_keys", []) if isinstance(payload, dict) else []
        return [
            {"id": entry["id"], "label": entry["label"]}
            for entry in entries
            if isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and isinstance(entry.get("label"), str)
        ]

    @staticmethod
    def keyring_status() -> tuple[bool, bool, str]:
        """Return availability, security expectation, and a UI-safe explanation."""
        try:
            backend = keyring.get_keyring()
        except Exception:
            return False, False, "İşletim sistemi anahtar kasası başlatılamadı."
        if isinstance(backend, FailKeyring) or getattr(backend, "priority", 0) <= 0:
            return False, False, "Kullanılabilir bir işletim sistemi anahtar kasası yok. Linux'ta Secret Service/KWallet kurun."
        backend_name = f"{backend.__class__.__module__}.{backend.__class__.__name__}".lower()
        secure_markers = ("macos", "winvault", "secretservice", "kwallet")
        if any(marker in backend_name for marker in secure_markers):
            return True, True, "Anahtarlar işletim sistemi güvenli kasasında saklanır."
        return True, False, "Anahtar kasası kullanılabilir; ancak bu backendin şifreleme politikasını kurumunuzla doğrulayın."

    def resolved_keys(self) -> list[tuple[str, str]]:
        available, _, _ = self.keyring_status()
        if not available:
            return []
        resolved = []
        for entry in self.list_keys():
            try:
                secret = keyring.get_password(SERVICE_NAME, entry["id"])
            except Exception:
                continue
            if secret:
                resolved.append((entry["label"], secret))
        return resolved

    def add_key(self, label: str, secret: str) -> None:
        available, _, message = self.keyring_status()
        if not available:
            raise RuntimeError(message)
        clean_label = label.strip()
        clean_secret = secret.strip()
        if not clean_label or len(clean_label) > MAX_LABEL_LENGTH or any(ord(char) < 32 for char in clean_label):
            raise ValueError("Anahtar etiketi 1-64 yazdırılabilir karakter olmalı.")
        if not KEY_PATTERN.fullmatch(clean_secret):
            raise ValueError("API anahtarı biçimi geçersiz görünüyor.")
        if any(entry["label"].casefold() == clean_label.casefold() for entry in self.list_keys()):
            raise ValueError("Bu etiket zaten kullanılıyor.")
        entry = {"id": str(uuid.uuid4()), "label": clean_label}
        entries = self.list_keys()
        entries.append(entry)
        keyring.set_password(SERVICE_NAME, entry["id"], clean_secret)
        try:
            self._write_entries(entries)
        except Exception:
            # Do not leave an unreachable secret behind if the local index cannot be saved.
            try:
                keyring.delete_password(SERVICE_NAME, entry["id"])
            except Exception:
                pass
            raise

    def delete_key(self, entry_id: str) -> None:
        if not any(entry["id"] == entry_id for entry in self.list_keys()):
            return
        entries = [entry for entry in self.list_keys() if entry["id"] != entry_id]
        self._write_entries(entries)
        try:
            keyring.delete_password(SERVICE_NAME, entry_id)
        except keyring.errors.PasswordDeleteError:
            pass

    @staticmethod
    def _write_entries(entries: list[dict[str, str]]) -> None:
        payload = json.dumps({"api_keys": entries}, ensure_ascii=False, indent=2) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="settings-", suffix=".json", dir=SETTINGS_PATH.parent, text=True
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.chmod(0o600)
            temporary_path.replace(SETTINGS_PATH)
        finally:
            if temporary_path.exists():
                temporary_path.unlink(missing_ok=True)
