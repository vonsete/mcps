#!/usr/bin/env python3
"""
MCP server for SSL/TLS certificate checks.
No API key required — uses Python's built-in ssl module.
"""

import sys
import json
import ssl
import socket
import datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "ssl_check_cert",
        "description": "Check SSL/TLS certificate for a host: expiry, issuer, subject, SANs, chain info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to check (e.g. 'google.com')"},
                "port": {"type": "integer", "description": "Port (default 443)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "ssl_check_expiry",
        "description": "Quick check of SSL certificate expiry date and days remaining.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to check"},
                "port": {"type": "integer", "description": "Port (default 443)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "ssl_check_protocols",
        "description": "Check which TLS protocol versions a server supports (TLS 1.0, 1.1, 1.2, 1.3).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to check"},
                "port": {"type": "integer", "description": "Port (default 443)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "ssl_bulk_expiry_check",
        "description": "Check SSL expiry for multiple hosts at once. Returns days remaining for each.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of hostnames to check",
                },
                "port": {"type": "integer", "description": "Port (default 443)"},
            },
            "required": ["hosts"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def get_cert(host, port=443, timeout=10):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(), ssock.version(), ssock.cipher()


def parse_cert(cert):
    """Extract useful fields from a certificate dict."""
    def fmt_dn(dn):
        return {k: v for entry in dn for k, v in entry}

    subject    = fmt_dn(cert.get("subject", []))
    issuer     = fmt_dn(cert.get("issuer", []))
    not_before = cert.get("notBefore", "")
    not_after  = cert.get("notAfter", "")
    sans       = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    expiry_dt  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    days_left  = (expiry_dt - datetime.datetime.utcnow()).days

    return {
        "subject":      subject.get("commonName"),
        "issuer_cn":    issuer.get("commonName"),
        "issuer_org":   issuer.get("organizationName"),
        "not_before":   not_before,
        "not_after":    not_after,
        "days_remaining": days_left,
        "expired":      days_left < 0,
        "expiring_soon": 0 <= days_left <= 30,
        "san":          sans,
        "serial":       cert.get("serialNumber"),
        "version":      cert.get("version"),
    }


def handle_ssl_check_cert(args):
    host = args.get("host")
    port = int(args.get("port", 443))
    cert, tls_version, cipher = get_cert(host, port)
    result = parse_cert(cert)
    result["tls_version"] = tls_version
    result["cipher"]      = cipher[0] if cipher else None
    result["host"]        = host
    result["port"]        = port
    return result


def handle_ssl_check_expiry(args):
    host = args.get("host")
    port = int(args.get("port", 443))
    cert, _, _ = get_cert(host, port)
    p = parse_cert(cert)
    return {
        "host":           host,
        "port":           port,
        "not_after":      p["not_after"],
        "days_remaining": p["days_remaining"],
        "expired":        p["expired"],
        "expiring_soon":  p["expiring_soon"],
    }


def handle_ssl_check_protocols(args):
    host = args.get("host")
    port = int(args.get("port", 443))
    results = {}

    protocols = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    for name, version in protocols.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    results[name] = "supported"
        except ssl.SSLError:
            results[name] = "not supported"
        except Exception as e:
            results[name] = f"error: {e}"

    return {"host": host, "port": port, "protocols": results}


def handle_ssl_bulk_expiry_check(args):
    hosts = args.get("hosts", [])
    port  = int(args.get("port", 443))
    results = []
    for host in hosts:
        try:
            cert, _, _ = get_cert(host, port, timeout=5)
            p = parse_cert(cert)
            results.append({
                "host":           host,
                "days_remaining": p["days_remaining"],
                "not_after":      p["not_after"],
                "expired":        p["expired"],
                "expiring_soon":  p["expiring_soon"],
                "status":         "ok",
            })
        except Exception as e:
            results.append({"host": host, "status": "error", "error": str(e)})
    # Sort by days_remaining ascending (errors last)
    results.sort(key=lambda x: x.get("days_remaining", 9999))
    return {"results": results, "total": len(results)}


HANDLERS = {
    "ssl_check_cert":         handle_ssl_check_cert,
    "ssl_check_expiry":       handle_ssl_check_expiry,
    "ssl_check_protocols":    handle_ssl_check_protocols,
    "ssl_bulk_expiry_check":  handle_ssl_bulk_expiry_check,
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


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

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
                "serverInfo": {"name": "ssl-mcp", "version": "1.0.0"},
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
