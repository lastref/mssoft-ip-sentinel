"""Build a clean, manifest-controlled source ZIP without local reports or secrets."""
from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "distribution_manifest.txt"
DIST = ROOT / "dist"


def main() -> None:
    files = [line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    missing = [name for name in files if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit("Eksik manifest dosyaları: " + ", ".join(missing))
    DIST.mkdir(exist_ok=True)
    archive_base = DIST / "MSSOFT_IP_Sentinel_source"
    temporary_root = DIST / "_source_stage"
    if temporary_root.exists():
        shutil.rmtree(temporary_root)
    stage = temporary_root / "MSSOFT_IP_Sentinel"
    stage.mkdir(parents=True)
    try:
        for name in files:
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        archive = shutil.make_archive(str(archive_base), "zip", root_dir=temporary_root, base_dir="MSSOFT_IP_Sentinel")
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    print(archive)


if __name__ == "__main__":
    main()
