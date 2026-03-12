#!/usr/bin/env python3
"""
MCP server for IP Geolocation.
Uses ip-api.com — no API key required (free tier, 45 req/min).
"""

import sys
import json
import urllib.request
import urllib.parse


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

def http_get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-geoip/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

FIELDS = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

TOOLS = [
    {
        "name": "geoip_lookup",
        "description": "Geolocate an IP address: country, city, coordinates, ISP, ASN, timezone, proxy/VPN detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to geolocate (e.g. '8.8.8.8'). Use 'me' for your own public IP."},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "geoip_bulk_lookup",
        "description": "Geolocate multiple IP addresses at once (up to 100).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IP addresses to geolocate",
                },
            },
            "required": ["ips"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def parse_result(data):
    if data.get("status") == "fail":
        return {"error": data.get("message"), "ip": data.get("query")}
    return {
        "ip":            data.get("query"),
        "continent":     data.get("continent"),
        "country":       data.get("country"),
        "country_code":  data.get("countryCode"),
        "region":        data.get("regionName"),
        "city":          data.get("city"),
        "zip":           data.get("zip"),
        "lat":           data.get("lat"),
        "lon":           data.get("lon"),
        "timezone":      data.get("timezone"),
        "currency":      data.get("currency"),
        "isp":           data.get("isp"),
        "org":           data.get("org"),
        "asn":           data.get("as"),
        "asn_name":      data.get("asname"),
        "reverse_dns":   data.get("reverse"),
        "mobile":        data.get("mobile"),
        "proxy_vpn":     data.get("proxy"),
        "hosting":       data.get("hosting"),
    }


def handle_geoip_lookup(args):
    ip = args.get("ip", "")
    target = "" if ip in ("me", "self", "") else f"/{urllib.parse.quote(ip)}"
    data = http_get(f"http://ip-api.com/json{target}?fields={FIELDS}")
    return parse_result(data)


def handle_geoip_bulk_lookup(args):
    ips = args.get("ips", [])
    if not ips:
        return {"results": []}
    # ip-api.com batch endpoint
    payload = json.dumps([{"query": ip, "fields": FIELDS} for ip in ips]).encode()
    req = urllib.request.Request(
        "http://ip-api.com/batch",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "mcp-geoip/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.loads(r.read().decode())
    return {"results": [parse_result(d) for d in data], "total": len(data)}


HANDLERS = {
    "geoip_lookup":       handle_geoip_lookup,
    "geoip_bulk_lookup":  handle_geoip_bulk_lookup,
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
                "serverInfo": {"name": "geoip-mcp", "version": "1.0.0"},
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
