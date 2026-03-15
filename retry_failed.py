#!/usr/bin/env python3
"""Reintenta subir los ficheros pendientes a Internxt: ZIPs, YARAs y JSONs de análisis."""
import json, subprocess
from pathlib import Path

INTERNXT        = "/usr/local/bin/internxt.py"
FAILED          = Path("/data/state/failed")
FAILED_YARA_DIR = Path("/data/state/failed_yara")
FAILED_JSON_DIR = Path("/data/state/failed_json")
SEEN_DB         = Path("/data/state/seen.json")


def upload(local_path, remote_folder):
    cmd = ["python3", INTERNXT, "upload", str(local_path), remote_folder]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())


def load_seen():
    if SEEN_DB.exists():
        return set(json.loads(SEEN_DB.read_text()))
    return set()


def save_seen(seen):
    SEEN_DB.write_text(json.dumps(sorted(seen)))


def retry_zips():
    zips = sorted(FAILED.glob("*.zip"))
    print(f"[*] ZIPs pendientes: {len(zips)}")
    seen = load_seen()
    ok = fail = skip = 0
    for zf in zips:
        sha256 = zf.stem
        if zf.stat().st_size == 0:
            print(f"  → {sha256[:16]}... 0 bytes, descartando")
            zf.unlink(missing_ok=True)
            (FAILED / f"{sha256}.json").unlink(missing_ok=True)
            skip += 1
            continue
        meta_f = FAILED / f"{sha256}.json"
        meta   = json.loads(meta_f.read_text()) if meta_f.exists() else {}
        folder = meta.get("remote_folder", "/malware")
        print(f"  → {sha256[:16]}... ({zf.stat().st_size // 1024} KB) {folder}", end=" ", flush=True)
        try:
            upload(zf, folder)
            print("✓")
            seen.add(sha256)
            zf.unlink(missing_ok=True)
            meta_f.unlink(missing_ok=True)
            ok += 1
        except Exception as e:
            print(f"FAIL: {e}")
            fail += 1
    save_seen(seen)
    print(f"  ZIPs → OK: {ok}  Fallidos: {fail}  Descartados: {skip}\n")


def retry_by_dir(label, failed_dir, file_key):
    metas = sorted(failed_dir.glob("*.json"))
    print(f"[*] {label} pendientes: {len(metas)}")
    ok = fail = skip = 0
    for meta_f in metas:
        meta       = json.loads(meta_f.read_text())
        sha256     = meta["sha256"]
        local_path = Path(meta[file_key])
        folder     = meta["remote_folder"]
        if not local_path.exists():
            print(f"  → {sha256[:16]}... fichero local no encontrado, descartando")
            meta_f.unlink(missing_ok=True)
            skip += 1
            continue
        print(f"  → {sha256[:16]}... {local_path.name}", end=" ", flush=True)
        try:
            upload(local_path, folder)
            print("✓")
            meta_f.unlink(missing_ok=True)
            ok += 1
        except Exception as e:
            print(f"FAIL: {e}")
            fail += 1
    print(f"  {label} → OK: {ok}  Fallidos: {fail}  Descartados: {skip}\n")


if __name__ == "__main__":
    retry_zips()
    retry_by_dir("YARAs", FAILED_YARA_DIR, "local_yara")
    retry_by_dir("JSONs", FAILED_JSON_DIR, "local_json")
