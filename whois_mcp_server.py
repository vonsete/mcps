#!/usr/bin/env python3
"""
MCP server for WHOIS lookups.
Uses python-whois library — no API key required.
"""

import sys
import json
import whois
from ipwhois import IPWhois


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


def serialize(obj):
    """Convert whois result to JSON-serializable dict."""
    if isinstance(obj, list):
        return [serialize(i) for i in obj]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "whois_domain",
        "description": "Look up WHOIS information for a domain: registrar, dates, nameservers, contacts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to query (e.g. 'google.com', 'masorange.es')"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "whois_ip",
        "description": "Look up WHOIS information for an IP address: owner, org, country, abuse contact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to query (e.g. '8.8.8.8')"},
            },
            "required": ["ip"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_whois_domain(args):
    domain = args.get("domain")
    w = whois.whois(domain)

    return {
        "domain":       domain,
        "registrar":    serialize(w.registrar),
        "creation_date": serialize(w.creation_date),
        "expiration_date": serialize(w.expiration_date),
        "updated_date": serialize(w.updated_date),
        "status":       serialize(w.status),
        "nameservers":  serialize(w.name_servers),
        "emails":       serialize(w.emails),
        "org":          serialize(w.org),
        "country":      serialize(w.country),
        "dnssec":       serialize(w.dnssec),
    }


def handle_whois_ip(args):
    ip = args.get("ip")
    obj = IPWhois(ip)
    r   = obj.lookup_rdap(depth=1)

    network = r.get("network", {})
    return {
        "ip":           ip,
        "asn":          r.get("asn"),
        "asn_cidr":     r.get("asn_cidr"),
        "asn_country":  r.get("asn_country_code"),
        "asn_registry": r.get("asn_registry"),
        "asn_date":     r.get("asn_date"),
        "org":          network.get("name"),
        "handle":       network.get("handle"),
        "cidr":         network.get("cidr"),
        "country":      network.get("country"),
        "start_address": network.get("start_address"),
        "end_address":  network.get("end_address"),
        "emails":       list({
            c.get("contact", {}).get("email", [{}])[0].get("value", "")
            for c in r.get("objects", {}).values()
            if c.get("contact", {}).get("email")
        } - {""}),
    }


HANDLERS = {
    "whois_domain": handle_whois_domain,
    "whois_ip":     handle_whois_ip,
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
                "serverInfo": {"name": "whois-mcp", "version": "1.0.0"},
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
