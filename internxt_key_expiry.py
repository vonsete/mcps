#!/usr/bin/env python3
"""
internxt_key_expiry.py — Muestra la caducidad del token de Internxt.

Uso:
    python3 internxt_key_expiry.py
"""

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CRED_FILE = Path.home() / ".internxt-tools" / "credentials.json"


def decode_exp(token: str) -> datetime | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        data = json.loads(base64.b64decode(payload))
        exp = data.get("exp")
        return datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None
    except Exception:
        return None


def main():
    if not CRED_FILE.exists():
        print(f"No se encuentra {CRED_FILE}")
        sys.exit(1)

    creds = json.loads(CRED_FILE.read_text())
    now = datetime.now(tz=timezone.utc)

    for key in ("token", "new_token"):
        token = creds.get(key)
        if not token:
            continue
        exp = decode_exp(token)
        if not exp:
            print(f"{key}: sin fecha de expiración")
            continue
        delta = exp - now
        hours = delta.total_seconds() / 3600
        days  = delta.days

        if hours < 0:
            status = "⚠  EXPIRADA"
        elif hours < 24:
            status = f"⚠  expira en {hours:.1f} horas"
        else:
            status = f"✓  expira en {days} días"

        local_exp = exp.astimezone().strftime("%Y-%m-%d %H:%M %Z")
        print(f"{key:12s}: {local_exp}  [{status}]")


if __name__ == "__main__":
    main()
