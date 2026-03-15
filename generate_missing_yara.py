#!/usr/bin/env python3
"""
generate_missing_yara.py — Genera reglas YARA para muestras sin YARA en /data/yara/.

Flujo:
  1. Lista carpetas de Internxt /malware/{familia}/ → mapa sha256 → familia
  2. Para cada hash pendiente (sin .yar local):
     a. Descarga ZIP desde Internxt
     b. Descomprime (pyzipper, pass: infected) → extrae binario
     c. Genera regla YARA
     d. Guarda en /data/yara/{sha256}.yar
     e. Sube YARA a Internxt /malware/yara/
     f. Añade atributo YARA al evento MISP (si existe)

Uso:
    python3 generate_missing_yara.py [--limit N] [--dry-run]
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

warnings.filterwarnings("ignore")

try:
    import pyzipper
    _HAS_PYZIPPER = True
except ImportError:
    _HAS_PYZIPPER = False

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuración ──────────────────────────────────────────────────────────────

MISP_KEY_FILE = Path.home() / ".misp_key"
SEEN_DB       = Path("/data/state/seen.json")
LOCAL_YARA    = Path("/data/yara")
INTERNXT      = "/usr/local/bin/internxt.py"
INTERNXT_BASE = "/malware"
INTERNXT_YARA     = "/malware/yara"
INTERNXT_ANALYSIS = "/malware/analysis"
TMPDIR        = Path(tempfile.gettempdir()) / "yara_gen"
ANTIMALWARE_PY = Path("/data/antimalware/venv/bin/python3")
ANALYZE_SCRIPT = Path("/data/antimalware/analyze_sample.py")
LOCAL_ANALYSIS = Path("/data/analysis")

_YARA_BLACKLIST = [
    b"Windows", b"Microsoft", b"Program Files", b"System32",
    b"kernel32", b"ntdll", b"user32", b"advapi32",
    b"GetProcAddress", b"LoadLibrary", b"VirtualAlloc",
    b"This program", b"runtime error", b"MSVCRT",
    b"__cdecl", b"__stdcall",
]

# ── Internxt ───────────────────────────────────────────────────────────────────

def internxt_ls(remote_path: str) -> list[str]:
    """Lista contenido de una carpeta. Devuelve nombres de ficheros."""
    cmd = ["python3", INTERNXT, "ls", remote_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return []
    lines = result.stdout.splitlines()
    files = []
    for line in lines:
        line = line.strip()
        if line.startswith("📄") or (line and not line.startswith("📁") and not line.startswith("📁") and "/" not in line and "carpeta" not in line and "fichero" not in line):
            # extraer nombre del fichero
            name = re.sub(r"^[^\w]*", "", line).strip()
            if name:
                files.append(name)
    return files


def internxt_ls_raw(remote_path: str) -> str:
    cmd = ["python3", INTERNXT, "ls", remote_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def internxt_download(remote_path: str, local_dir: Path) -> Path | None:
    cmd = ["python3", INTERNXT, "download", remote_path, str(local_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    fname = remote_path.split("/")[-1]
    p = local_dir / fname
    return p if p.exists() else None


def internxt_upload(local_path: Path, remote_folder: str):
    cmd = ["python3", INTERNXT, "upload", str(local_path), remote_folder]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())


def build_hash_to_family() -> dict[str, str]:
    """Lista todas las carpetas de /malware/ y construye mapa sha256 → familia."""
    print("[*] Construyendo mapa sha256 → familia desde Internxt...")
    # Obtener carpetas
    raw = internxt_ls_raw(INTERNXT_BASE)
    folders = re.findall(r"📁\s+(\S+)/", raw)
    folders = [f for f in folders if f != "yara"]

    mapping = {}
    for folder in folders:
        raw_files = internxt_ls_raw(f"{INTERNXT_BASE}/{folder}")
        # Buscar líneas con sha256.zip (64 hex chars + .zip)
        hashes = re.findall(r"\b([0-9a-f]{64})\.zip\b", raw_files)
        for h in hashes:
            mapping[h] = folder
        print(f"  {folder}: {len(hashes)} ficheros")

    print(f"[*] Total mapeados: {len(mapping)} hashes en {len(folders)} carpetas\n")
    return mapping


# ── MISP ───────────────────────────────────────────────────────────────────────

def load_misp_config() -> dict | None:
    if not MISP_KEY_FILE.exists():
        return None
    cfg = json.loads(MISP_KEY_FILE.read_text())
    cfg["url"] = cfg["url"].rstrip("/")
    return cfg


def misp_find_event_id(cfg: dict, sha256: str) -> tuple[str | None, str | None]:
    """Devuelve (event_id, attr_id) para el sha256, o (None, None)."""
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    try:
        r = requests.post(
            f"{cfg['url']}/attributes/restSearch",
            json={"type": "sha256", "value": sha256, "returnFormat": "json"},
            headers=headers, verify=False, timeout=15,
        )
        attrs = r.json().get("response", {}).get("Attribute", [])
        if attrs:
            return attrs[0]["event_id"], str(attrs[0]["id"])
        return None, None
    except Exception:
        return None, None


def misp_create_event(cfg: dict, info: str, family: str) -> str | None:
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    try:
        r = requests.post(
            f"{cfg['url']}/events/add",
            json={"info": info, "threat_level_id": 2, "analysis": 1,
                  "distribution": 1,
                  "Tag": [{"name": f"malware:{family}"}, {"name": "tlp:amber"}]},
            headers=headers, verify=False, timeout=15,
        )
        return r.json().get("Event", {}).get("id")
    except Exception:
        return None


def misp_add_sha256(cfg: dict, event_id: str, sha256: str, comment: str = "") -> str | None:
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    try:
        r = requests.post(
            f"{cfg['url']}/attributes/add/{event_id}",
            json={"type": "sha256", "category": "Payload delivery",
                  "value": sha256, "to_ids": True, "comment": comment},
            headers=headers, verify=False, timeout=15,
        )
        attr = r.json().get("Attribute", {})
        return str(attr["id"]) if attr.get("id") else None
    except Exception:
        return None


def misp_add_yara(cfg: dict, event_id: str, sha256: str, yara_rule: str) -> bool:
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    try:
        r = requests.post(
            f"{cfg['url']}/attributes/add/{event_id}",
            json={"type": "yara", "category": "Artifacts dropped",
                  "value": yara_rule, "to_ids": False,
                  "comment": f"Auto-generated YARA for {sha256[:16]}"},
            headers=headers, verify=False, timeout=15,
        )
        return r.status_code in (200, 201)
    except Exception:
        return False


def misp_ensure_tag(cfg: dict, tag_name: str, colour: str = "#2c3e50") -> str | None:
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    try:
        r = requests.post(
            f"{cfg['url']}/tags/add",
            json={"name": tag_name, "colour": colour, "exportable": True},
            headers=headers, verify=False, timeout=10,
        )
        data = r.json()
        tag_id = (data.get("Tag") or {}).get("id")
        if tag_id:
            return str(tag_id)
        # Fallback: buscar por nombre
        r2 = requests.get(f"{cfg['url']}/tags/index", headers=headers,
                          verify=False, timeout=10)
        for t in r2.json().get("Tag", []):
            if t["name"] == tag_name:
                return str(t["id"])
    except Exception:
        pass
    return None


def misp_add_tags_to_event(cfg: dict, event_id: str, tags: list) -> int:
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    n = 0
    for tag_name in tags:
        tag_id = misp_ensure_tag(cfg, tag_name)
        if not tag_id:
            continue
        try:
            r = requests.post(
                f"{cfg['url']}/events/addTag/{event_id}/{tag_id}",
                headers=headers, verify=False, timeout=10,
            )
            if r.status_code in (200, 201):
                n += 1
        except Exception:
            pass
    return n


# ── Antimalware ────────────────────────────────────────────────────────────────

def analyze_with_antimalware(binary_path: Path, sha256: str, family: str) -> dict:
    if not ANTIMALWARE_PY.exists() or not ANALYZE_SCRIPT.exists():
        return {}
    LOCAL_ANALYSIS.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [str(ANTIMALWARE_PY), str(ANALYZE_SCRIPT),
             "--file", str(binary_path), "--sha256", sha256, "--family", family],
            capture_output=True, text=True, timeout=240,
        )
        out_json = LOCAL_ANALYSIS / f"{sha256}.json"
        if out_json.exists():
            return json.loads(out_json.read_text())
    except Exception:
        pass
    return {}


def misp_add_tags_to_attribute(cfg: dict, attr_id: str, tags: list) -> int:
    headers = {"Authorization": cfg["key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    added = 0
    for tag_name in tags:
        tag_id = misp_ensure_tag(cfg, tag_name)
        if not tag_id:
            continue
        try:
            r = requests.post(
                f"{cfg['url']}/attributes/addTag/{attr_id}/{tag_id}",
                headers=headers, verify=False, timeout=10,
            )
            if r.status_code in (200, 201):
                added += 1
        except Exception:
            pass
    return added


# ── Extracción y YARA ─────────────────────────────────────────────────────────

def extract_binary(zip_path: Path, tmpdir: Path) -> Path | None:
    openers = []
    if _HAS_PYZIPPER:
        openers.append(lambda p: pyzipper.AESZipFile(p, "r"))
    openers.append(lambda p: zipfile.ZipFile(p, "r"))
    for opener in openers:
        try:
            with opener(zip_path) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                if not names:
                    return None
                zf.extractall(tmpdir, pwd=b"infected")
                return tmpdir / names[0]
        except Exception:
            continue
    return None


def generate_yara_rule(binary_path: Path, sha256: str, family: str) -> str:
    data = binary_path.read_bytes()

    if data[:2] == b"MZ":
        file_type_cond = "uint16(0) == 0x5A4D"
    elif data[:4] == b"\x7fELF":
        file_type_cond = "uint32(0) == 0x464C457F"
    else:
        file_type_cond = (f"filesize >= {max(1, len(data) - 4096)} "
                          f"and filesize <= {len(data) + 4096}")

    raw_strings = re.findall(rb"[\x20-\x7e]{8,}", data)
    selected, seen_s = [], set()
    for s in raw_strings:
        if len(selected) >= 15:
            break
        if s in seen_s or any(bl in s for bl in _YARA_BLACKLIST):
            continue
        decoded = s.decode("ascii", errors="replace")
        if len(set(decoded)) < 4:
            continue
        selected.append(decoded)
        seen_s.add(s)

    rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", f"{family}_{sha256[:12]}")
    lines = [
        f"rule {rule_name} {{",
        "    meta:",
        f'        description = "Auto-generated YARA rule for {family}"',
        f'        sha256      = "{sha256}"',
        f'        family      = "{family}"',
        f'        generated_by = "generate_missing_yara.py"',
        "",
        "    strings:",
    ]
    for i, s in enumerate(selected):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'        $s{i} = "{escaped}" ascii wide')

    threshold = min(3, len(selected))
    condition = (f"{file_type_cond} and {threshold} of ($s*)"
                 if threshold > 0 else file_type_cond)
    lines += ["", "    condition:", f"        {condition}", "}", ""]
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Genera YARA para muestras sin regla")
    ap.add_argument("--limit", type=int, default=0,
                    help="Máx. muestras a procesar (0 = todas)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Solo muestra qué haría, sin ejecutar")
    args = ap.parse_args()

    LOCAL_YARA.mkdir(parents=True, exist_ok=True)
    TMPDIR.mkdir(parents=True, exist_ok=True)

    misp_cfg = load_misp_config()

    # Construir mapa sha256 → familia desde Internxt
    hash_to_family = build_hash_to_family()

    # Hashes pendientes
    all_hashes = json.loads(SEEN_DB.read_text())
    existing   = {p.stem for p in LOCAL_YARA.glob("*.yar")}
    pending    = [h for h in all_hashes if h not in existing and h in hash_to_family]
    not_found  = [h for h in all_hashes if h not in existing and h not in hash_to_family]

    print(f"[*] Total hashes: {len(all_hashes)}")
    print(f"[*] Con YARA:     {len(existing)}")
    print(f"[*] Pendientes:   {len(pending)} (en Internxt)")
    print(f"[*] Sin ZIP:      {len(not_found)} (no localizados en Internxt)\n")

    if args.limit:
        pending = pending[:args.limit]
        print(f"[*] Procesando {len(pending)} muestras (--limit {args.limit})\n")

    ok = failed = 0

    for sha256 in pending:
        family     = hash_to_family[sha256]
        remote_zip = f"{INTERNXT_BASE}/{family}/{sha256}.zip"
        print(f"  → {sha256[:16]}... [{family}]", end=" ", flush=True)

        if args.dry_run:
            print("[dry-run]")
            continue

        # 1. Descargar ZIP desde Internxt
        zip_path = internxt_download(remote_zip, TMPDIR)
        if not zip_path:
            print("✗ descarga")
            failed += 1
            continue
        print("✓ DL", end=" ", flush=True)

        # 2. Extraer binario
        binary_path = extract_binary(zip_path, TMPDIR)
        zip_path.unlink(missing_ok=True)
        if not binary_path or not binary_path.exists():
            print("✗ extracción")
            failed += 1
            continue

        # 3. Análisis antimalware (mientras el binario existe)
        analysis = analyze_with_antimalware(binary_path, sha256, family)
        suggested_tags = analysis.get("suggested_tags", [])
        if suggested_tags:
            print(f"✓ AM({len(suggested_tags)})", end=" ", flush=True)

        # 4. Generar YARA
        yara_rule = None
        try:
            yara_rule = generate_yara_rule(binary_path, sha256, family)
        except Exception as e:
            print(f"✗ YARA({e})")
            failed += 1
        finally:
            binary_path.unlink(missing_ok=True)

        if yara_rule is None:
            continue

        # 5. Guardar local
        (LOCAL_YARA / f"{sha256}.yar").write_text(yara_rule)
        print("✓ local", end=" ", flush=True)

        # 6. Subir a Internxt (YARA + JSON de análisis)
        local_yar = LOCAL_YARA / f"{sha256}.yar"
        try:
            internxt_upload(local_yar, INTERNXT_YARA)
            print("✓ Internxt", end=" ", flush=True)
        except Exception as e:
            print(f"✗ Internxt({e})", end=" ", flush=True)

        analysis_json = LOCAL_ANALYSIS / f"{sha256}.json"
        if analysis_json.exists():
            try:
                internxt_upload(analysis_json, INTERNXT_ANALYSIS)
                print("✓ JSON", end=" ", flush=True)
            except Exception as e:
                print(f"✗ JSON({e})", end=" ", flush=True)

        # 7. MISP — buscar evento existente o crear uno nuevo por muestra
        event_id = attr_id = None
        if misp_cfg:
            event_id, attr_id = misp_find_event_id(misp_cfg, sha256)
            if event_id:
                # Evento ya existe (batch antiguo): solo añadir YARA
                ok_misp = misp_add_yara(misp_cfg, event_id, sha256, yara_rule)
                print("✓ MISP" if ok_misp else "✗ MISP", end=" ")
            else:
                # Sin evento: crear uno por muestra con sha256 + YARA
                event_id = misp_create_event(
                    misp_cfg, f"{family} — {sha256[:16]}", family)
                if event_id:
                    attr_id = misp_add_sha256(misp_cfg, event_id, sha256,
                                              comment=f"YARA backfill — {family}")
                    misp_add_yara(misp_cfg, event_id, sha256, yara_rule)
                    print("✓ MISP-new", end=" ")
                else:
                    print("✗ MISP-event", end=" ")

        # 8. Aplicar tags antimalware al atributo y al evento
        if misp_cfg and suggested_tags:
            if attr_id:
                misp_add_tags_to_attribute(misp_cfg, attr_id, suggested_tags)
            if event_id:
                n_tags = misp_add_tags_to_event(misp_cfg, event_id, suggested_tags)
                if n_tags:
                    print(f"✓ tags({n_tags})", end=" ")

        print()
        ok += 1

    print(f"\n{'='*50}")
    print(f"  OK           : {ok}")
    print(f"  Fallidos     : {failed}")
    print(f"  Sin ZIP local: {len(not_found)}")
    print(f"  YARA en {LOCAL_YARA}: {len(list(LOCAL_YARA.glob('*.yar')))}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
