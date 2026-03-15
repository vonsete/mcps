#!/usr/bin/env python3
"""
misp_to_unifi.py — Sincroniza IPs/CIDRs maliciosas desde MISP a un firewall
                   group de UniFi (MISP-C2-Blocklist).

Fuentes usadas (to_ids:True, ip-dst):
  - Feodo Tracker C2 IPs  (event 1897)
  - Maltrail IOC          (event 1914)
  - Emerging Threats      (event 1900)

Flujo:
  1. Extrae ip-dst con to_ids:True de los eventos fuente
  2. Crea o actualiza el firewall group 'MISP-C2-Blocklist' en UniFi
  3. (Opcional) Crea reglas WAN_IN y LAN_OUT si no existen

Uso:
    python3 misp_to_unifi.py [--dry-run] [--verbose]

Credenciales:
    MISP  : ~/.misp_key  (JSON: url, key)
    UniFi : ~/.unifi_key (JSON: host, user, password, [port], [site])
"""

import argparse
import ipaddress
import json
import sys
import warnings
from pathlib import Path

import requests

warnings.filterwarnings("ignore")

# ── Configuración ──────────────────────────────────────────────────────────────

MISP_KEY_FILE  = Path.home() / ".misp_key"
UNIFI_KEY_FILE = Path.home() / ".unifi_key"

# Eventos MISP fuente (id: nombre)
MISP_SOURCE_EVENTS = {
    1897: "Feodo Tracker",
    1914: "Maltrail",
    1900: "Emerging Threats",
}

UNIFI_GROUP_NAME = "MISP-C2-Blocklist"

# UniFi limita los grupos a 2000 entradas — priorizamos Feodo > Maltrail > ET
MAX_IPS = 2000

# ── MISP ───────────────────────────────────────────────────────────────────────

def load_misp_config() -> dict:
    if not MISP_KEY_FILE.exists():
        sys.exit(f"[!] No se encuentra {MISP_KEY_FILE}")
    cfg = json.loads(MISP_KEY_FILE.read_text())
    cfg["url"] = cfg["url"].rstrip("/")
    return cfg


def fetch_c2_ips(cfg: dict, verbose: bool = False) -> list[str]:
    """Extrae ip-dst con to_ids:True de los eventos fuente, priorizados."""
    headers = {
        "Authorization": cfg["key"],
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # Prioridad: Feodo primero, luego Maltrail, luego ET
    ordered = sorted(MISP_SOURCE_EVENTS.items(), key=lambda x: (x[0] != 1897, x[0] != 1914))
    ips_by_source = {}

    for event_id, name in ordered:
        r = requests.post(
            f"{cfg['url']}/attributes/restSearch",
            json={"eventid": event_id, "type": "ip-dst", "to_ids": True,
                  "returnFormat": "json", "limit": 5000},
            headers=headers, verify=False, timeout=30,
        )
        attrs = r.json().get("response", {}).get("Attribute", [])
        ips_by_source[name] = [a["value"] for a in attrs]
        if verbose:
            print(f"  {name}: {len(ips_by_source[name])} IPs/CIDRs")

    # Validar y deduplicar manteniendo prioridad
    seen = set()
    result = []
    for name, ips in ips_by_source.items():
        for ip in ips:
            if ip in seen:
                continue
            try:
                # Validar que es IP o CIDR válido
                ipaddress.ip_network(ip, strict=False)
                seen.add(ip)
                result.append(ip)
            except ValueError:
                if verbose:
                    print(f"    [!] IP inválida ignorada: {ip}")

    if len(result) > MAX_IPS:
        print(f"  [!] {len(result)} entradas superan el límite de {MAX_IPS} — truncando")
        result = result[:MAX_IPS]

    return result


# ── UniFi ──────────────────────────────────────────────────────────────────────

def load_unifi_config() -> dict:
    if not UNIFI_KEY_FILE.exists():
        sys.exit(f"[!] No se encuentra {UNIFI_KEY_FILE}")
    cfg = json.loads(UNIFI_KEY_FILE.read_text())
    cfg.setdefault("port", 443)
    cfg.setdefault("site", "default")
    return cfg


def unifi_session(cfg: dict) -> requests.Session:
    s = requests.Session()
    s.verify = False
    base = f"https://{cfg['host']}:{cfg['port']}"

    # Login
    r = s.post(f"{base}/api/login",
               json={"username": cfg["user"], "password": cfg["password"]},
               timeout=15)
    if r.status_code not in (200, 204):
        sys.exit(f"[!] Login UniFi fallido: {r.status_code} {r.text[:100]}")

    # CSRF token (UniFi OS)
    csrf = r.headers.get("X-CSRF-Token") or r.cookies.get("csrf_token", "")
    if csrf:
        s.headers.update({"X-CSRF-Token": csrf})

    return s, base


def get_firewall_groups(s: requests.Session, base: str, site: str) -> list[dict]:
    r = s.get(f"{base}/api/s/{site}/rest/firewallgroup", timeout=15)
    return r.json().get("data", [])


def upsert_firewall_group(s: requests.Session, base: str, site: str,
                          name: str, members: list[str],
                          dry_run: bool = False) -> str | None:
    """Crea o actualiza el firewall group. Devuelve el _id."""
    groups = get_firewall_groups(s, base, site)
    existing = next((g for g in groups if g.get("name") == name), None)

    payload = {
        "name":         name,
        "group_type":   "address-group",
        "group_members": members,
    }

    if dry_run:
        action = "ACTUALIZAR" if existing else "CREAR"
        print(f"  [dry-run] {action} grupo '{name}' con {len(members)} entradas")
        return existing.get("_id") if existing else "dry-run-id"

    if existing:
        gid = existing["_id"]
        r = s.put(f"{base}/api/s/{site}/rest/firewallgroup/{gid}",
                  json={**payload, "site_id": site}, timeout=15)
        if r.status_code not in (200, 201):
            print(f"  [!] Error actualizando grupo: {r.status_code} {r.text[:100]}")
            return None
        print(f"  ✓ Grupo '{name}' actualizado ({len(members)} entradas)")
    else:
        r = s.post(f"{base}/api/s/{site}/rest/firewallgroup",
                   json=payload, timeout=15)
        if r.status_code not in (200, 201):
            print(f"  [!] Error creando grupo: {r.status_code} {r.text[:100]}")
            return None
        existing = r.json().get("data", [{}])[0]
        print(f"  ✓ Grupo '{name}' creado ({len(members)} entradas)")

    return r.json().get("data", [{}])[0].get("_id")


def ensure_firewall_rule(s: requests.Session, base: str, site: str,
                         name: str, ruleset: str, group_id: str,
                         dry_run: bool = False):
    """Crea la regla de bloqueo si no existe."""
    r = s.get(f"{base}/api/s/{site}/rest/firewallrule", timeout=15)
    rules = r.json().get("data", [])
    existing = next((ru for ru in rules if ru.get("name") == name), None)

    if existing:
        print(f"  ✓ Regla '{name}' ya existe (id: {existing['_id']})")
        return

    # WAN_IN: bloquear tráfico entrante desde IPs maliciosas
    # LAN_OUT: bloquear tráfico saliente hacia IPs maliciosas
    if ruleset == "WAN_IN":
        payload = {
            "name":       name,
            "ruleset":    "WAN_IN",
            "rule_index": 20000,
            "action":     "drop",
            "enabled":    True,
            "logging":    True,
            "protocol":   "all",
            "src_firewallgroup_ids": [group_id],
            "dst_firewallgroup_ids": [],
            "src_address": "",
            "dst_address": "",
        }
    else:  # LAN_OUT
        payload = {
            "name":       name,
            "ruleset":    "LAN_OUT",
            "rule_index": 20001,
            "action":     "drop",
            "enabled":    True,
            "logging":    True,
            "protocol":   "all",
            "src_firewallgroup_ids": [],
            "dst_firewallgroup_ids": [group_id],
            "src_address": "",
            "dst_address": "",
        }

    if dry_run:
        print(f"  [dry-run] CREAR regla '{name}' en {ruleset}")
        return

    r = s.post(f"{base}/api/s/{site}/rest/firewallrule",
               json=payload, timeout=15)
    if r.status_code in (200, 201):
        print(f"  ✓ Regla '{name}' creada en {ruleset}")
    else:
        print(f"  [!] Error creando regla '{name}': {r.status_code} {r.text[:100]}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Sincroniza IPs C2 de MISP a UniFi")
    ap.add_argument("--dry-run",  action="store_true", help="Muestra qué haría sin ejecutar")
    ap.add_argument("--verbose",  action="store_true", help="Salida detallada")
    ap.add_argument("--no-rules", action="store_true", help="Solo actualizar el grupo, no crear reglas")
    args = ap.parse_args()

    print("=" * 55)
    print("  MISP → UniFi C2 Blocklist Sync")
    print("=" * 55)

    # 1. Extraer IPs de MISP
    print("\n[1] Extrayendo IPs de MISP...")
    misp_cfg = load_misp_config()
    ips = fetch_c2_ips(misp_cfg, verbose=args.verbose)
    print(f"  Total a bloquear: {len(ips)} entradas")

    if not ips:
        print("  Sin IPs que bloquear. Saliendo.")
        return

    if args.verbose:
        for ip in ips:
            print(f"    {ip}")

    # 2. Conectar a UniFi
    print("\n[2] Conectando a UniFi...")
    unifi_cfg = load_unifi_config()
    s, base = unifi_session(unifi_cfg)
    site = unifi_cfg["site"]
    print(f"  ✓ Conectado a {unifi_cfg['host']} (site: {site})")

    # 3. Crear/actualizar firewall group
    print(f"\n[3] Actualizando grupo '{UNIFI_GROUP_NAME}'...")
    group_id = upsert_firewall_group(s, base, site, UNIFI_GROUP_NAME, ips, args.dry_run)

    # 4. Crear reglas si no existen
    if not args.no_rules and group_id:
        print("\n[4] Verificando reglas de firewall...")
        ensure_firewall_rule(s, base, site,
                             "MISP-C2-Block-Inbound", "WAN_IN", group_id, args.dry_run)
        ensure_firewall_rule(s, base, site,
                             "MISP-C2-Block-Outbound", "LAN_OUT", group_id, args.dry_run)

    print("\n" + "=" * 55)
    print(f"  Sync completado: {len(ips)} IPs/CIDRs en '{UNIFI_GROUP_NAME}'")
    print("=" * 55)


if __name__ == "__main__":
    main()
