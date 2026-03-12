#!/usr/bin/env python3
"""
MCP server for crt.sh — Certificate Transparency log search.
No API key required. Free and public.
"""

import sys
import json
import urllib.request
import urllib.parse
import re
from datetime import datetime, timezone


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


def crtsh_query(q, deduplicate=True):
    params = urllib.parse.urlencode({"q": q, "output": "json"})
    url    = f"https://crt.sh/?{params}"
    req    = urllib.request.Request(url, headers={
        "User-Agent": "mcp-crtsh/1.0",
        "Accept":     "application/json",
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read().decode())
    if deduplicate:
        seen = set()
        deduped = []
        for c in data:
            key = c.get("id")
            if key not in seen:
                seen.add(key)
                deduped.append(c)
        return deduped
    return data


def _days_until(date_str):
    if not date_str:
        return None
    try:
        dt  = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (dt - now).days
    except Exception:
        return None


def _fmt_cert(c):
    not_after  = c.get("not_after", "")
    not_before = c.get("not_before", "")
    days_left  = _days_until(not_after)
    return {
        "id":           c.get("id"),
        "logged_at":    (c.get("logged_at") or "")[:10] or None,
        "not_before":   (not_before or "")[:10] or None,
        "not_after":    (not_after or "")[:10] or None,
        "days_left":    days_left,
        "expired":      days_left is not None and days_left < 0,
        "common_name":  c.get("common_name"),
        "san":          c.get("name_value", "").splitlines(),
        "issuer":       c.get("issuer_name", "").replace("\n", ", "),
    }


TOOLS = [
    {
        "name": "crtsh_search",
        "description": "Search Certificate Transparency logs on crt.sh. Supports domain, wildcard (%.example.com), email, or organization name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":          {"type": "string",  "description": "Domain, %.domain.com wildcard, email, or organization name"},
                "include_expired":{"type": "boolean", "description": "Include expired certificates (default false)"},
                "limit":          {"type": "integer", "description": "Max results to return (default 50)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "crtsh_subdomains",
        "description": "Extract all unique subdomains discovered via Certificate Transparency for a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":          {"type": "string",  "description": "Root domain (e.g. 'example.com')"},
                "include_expired": {"type": "boolean", "description": "Include subdomains from expired certs (default true)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "crtsh_cert_detail",
        "description": "Get full details of a specific certificate by its crt.sh ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cert_id": {"type": "integer", "description": "Certificate ID from crt.sh"},
            },
            "required": ["cert_id"],
        },
    },
    {
        "name": "crtsh_expiring",
        "description": "Find certificates for a domain that are expiring soon or already expired.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":  {"type": "string",  "description": "Domain to check"},
                "days":    {"type": "integer", "description": "Warn if expiring within this many days (default 30)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "crtsh_issuers",
        "description": "Show certificate authorities (CAs) that have issued certificates for a domain, with counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to analyze"},
            },
            "required": ["domain"],
        },
    },
]


def handle_crtsh_search(args):
    q               = args["query"]
    limit           = int(args.get("limit", 50))
    include_expired = bool(args.get("include_expired", False))
    certs           = crtsh_query(q)
    now             = datetime.now(timezone.utc)
    if not include_expired:
        certs = [c for c in certs if _days_until(c.get("not_after")) is None or _days_until(c.get("not_after")) >= 0]
    certs = certs[:limit]
    return {
        "query":  q,
        "total":  len(certs),
        "certs":  [_fmt_cert(c) for c in certs],
    }


def handle_crtsh_subdomains(args):
    domain          = args["domain"]
    include_expired = bool(args.get("include_expired", True))
    certs           = crtsh_query(f"%.{domain}")
    subdomains      = set()
    for c in certs:
        if not include_expired:
            if _days_until(c.get("not_after")) is not None and _days_until(c.get("not_after")) < 0:
                continue
        for name in c.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                subdomains.add(name)
        cn = (c.get("common_name") or "").strip().lower().lstrip("*.")
        if cn.endswith(domain) and cn != domain:
            subdomains.add(cn)
    sorted_subs = sorted(subdomains)
    return {
        "domain":     domain,
        "count":      len(sorted_subs),
        "subdomains": sorted_subs,
    }


def handle_crtsh_cert_detail(args):
    cert_id = int(args["cert_id"])
    url     = f"https://crt.sh/?id={cert_id}&output=json"
    req     = urllib.request.Request(url, headers={"User-Agent": "mcp-crtsh/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read().decode())
    if isinstance(data, list):
        data = data[0] if data else {}
    return _fmt_cert(data)


def handle_crtsh_expiring(args):
    domain     = args["domain"]
    warn_days  = int(args.get("days", 30))
    certs      = crtsh_query(f"%.{domain}") + crtsh_query(domain)
    results    = []
    for c in certs:
        days = _days_until(c.get("not_after"))
        if days is not None and days <= warn_days:
            fc = _fmt_cert(c)
            fc["status"] = "EXPIRED" if days < 0 else f"expires in {days}d"
            results.append(fc)
    # Deduplicate by id
    seen = set()
    deduped = []
    for r in results:
        if r["id"] not in seen:
            seen.add(r["id"])
            deduped.append(r)
    deduped.sort(key=lambda x: x.get("days_left") or -9999)
    return {
        "domain":      domain,
        "warn_days":   warn_days,
        "count":       len(deduped),
        "certificates":deduped,
    }


def handle_crtsh_issuers(args):
    domain = args["domain"]
    certs  = crtsh_query(f"%.{domain}") + crtsh_query(domain)
    issuers = {}
    for c in certs:
        issuer = c.get("issuer_name", "unknown").replace("\n", ", ")
        issuers[issuer] = issuers.get(issuer, 0) + 1
    sorted_issuers = sorted(issuers.items(), key=lambda x: -x[1])
    return {
        "domain":  domain,
        "total_certs": len(certs),
        "issuers": [{"issuer": k, "count": v} for k, v in sorted_issuers],
    }


HANDLERS = {
    "crtsh_search":     handle_crtsh_search,
    "crtsh_subdomains": handle_crtsh_subdomains,
    "crtsh_cert_detail":handle_crtsh_cert_detail,
    "crtsh_expiring":   handle_crtsh_expiring,
    "crtsh_issuers":    handle_crtsh_issuers,
}


def handle_call(id, name, args):
    handler = HANDLERS.get(name)
    if not handler:
        error(id, -32601, f"Unknown tool: {name}")
        return
    try:
        result = handler(args)
        respond(id, text_result(result))
    except Exception as e:
        respond(id, {"content": [{"type": "text", "text": f"[error]: {e}"}], "isError": True})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        id     = msg.get("id")
        if method == "initialize":
            respond(id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "crtsh-mcp", "version": "1.0.0"},
            })
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            respond(id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params", {})
            handle_call(id, params.get("name"), params.get("arguments", {}))
        elif id is not None:
            error(id, -32601, f"Method not found: {method}")

if __name__ == "__main__":
    main()
