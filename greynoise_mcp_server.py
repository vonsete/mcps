#!/usr/bin/env python3
"""
MCP server for GreyNoise — context about IPs scanning the internet.
Community API is free (no key). Enterprise features read key from ~/.greynoise_key
"""

import sys
import json
import os
import urllib.request
import urllib.parse


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}

def load_key():
    path = os.path.expanduser("~/.greynoise_key")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read().strip() or None

def gn_get(path, use_key=False):
    url     = f"https://api.greynoise.io{path}"
    headers = {"Accept": "application/json", "User-Agent": "mcp-greynoise/1.0"}
    if use_key:
        key = load_key()
        if key:
            headers["key"] = key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "greynoise_ip",
        "description": "Check an IP against GreyNoise. Shows if it's a known internet scanner, its classification (benign/malicious/unknown), tags and metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "greynoise_ip_quick",
        "description": "Quick GreyNoise check for multiple IPs at once — returns noise/riot/unknown classification only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IP addresses (up to 500, requires API key)",
                },
            },
            "required": ["ips"],
        },
    },
    {
        "name": "greynoise_riot",
        "description": "Check if an IP belongs to a known benign service (RIOT — Rule It Out). Identifies Google, Cloudflare, AWS, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "greynoise_search",
        "description": "Search GreyNoise with GNQL queries (requires API key). E.g. 'tags:MIRAI classification:malicious'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "GNQL query string"},
                "size":  {"type": "integer", "description": "Number of results (default 10, max 10000)"},
            },
            "required": ["query"],
        },
    },
]


def handle_greynoise_ip(args):
    ip   = args["ip"]
    # Try enterprise endpoint first, fall back to community
    key  = load_key()
    if key:
        try:
            data = gn_get(f"/v2/noise/context/{ip}", use_key=True)
            return {
                "ip":             ip,
                "seen":           data.get("seen"),
                "classification": data.get("classification"),
                "noise":          data.get("noise"),
                "riot":           data.get("riot"),
                "name":           data.get("name"),
                "tags":           data.get("tags", []),
                "country":        data.get("metadata", {}).get("country"),
                "city":           data.get("metadata", {}).get("city"),
                "org":            data.get("metadata", {}).get("organization"),
                "asn":            data.get("metadata", {}).get("asn"),
                "os":             data.get("metadata", {}).get("os"),
                "last_seen":      data.get("last_seen"),
                "first_seen":     data.get("first_seen"),
                "actor":          data.get("actor"),
                "vpn":            data.get("vpn"),
                "tor":            data.get("metadata", {}).get("tor"),
                "cve":            data.get("cve", []),
            }
        except Exception:
            pass
    # Community API (free, no key)
    try:
        data = gn_get(f"/v3/community/{ip}")
        return {
            "ip":             ip,
            "noise":          data.get("noise"),
            "riot":           data.get("riot"),
            "classification": data.get("classification"),
            "name":           data.get("name"),
            "link":           data.get("link"),
            "last_seen":      data.get("last_seen"),
            "message":        data.get("message"),
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            d = json.loads(body)
            return {"ip": ip, "message": d.get("message", body), "noise": False, "riot": False}
        except Exception:
            return {"ip": ip, "error": body}


def handle_greynoise_ip_quick(args):
    ips = args.get("ips", [])
    key = load_key()
    if not key:
        # Fall back to individual community lookups
        return {"results": [handle_greynoise_ip({"ip": ip}) for ip in ips[:10]]}
    headers = {"key": key, "Content-Type": "application/json", "User-Agent": "mcp-greynoise/1.0"}
    body    = json.dumps(ips).encode()
    req     = urllib.request.Request(
        "https://api.greynoise.io/v2/noise/multi/quick",
        data=body, method="POST", headers=headers,
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read().decode())
    return {"results": data}


def handle_greynoise_riot(args):
    ip   = args["ip"]
    data = gn_get(f"/v2/riot/{ip}", use_key=True)
    return {
        "ip":            ip,
        "riot":          data.get("riot"),
        "name":          data.get("name"),
        "category":      data.get("category"),
        "description":   data.get("description"),
        "explanation":   data.get("explanation"),
        "last_updated":  data.get("last_updated"),
        "trust_level":   data.get("trust_level"),
        "reference":     data.get("reference"),
    }


def handle_greynoise_search(args):
    key = load_key()
    if not key:
        return {"error": "API key required for GNQL search. Save it to ~/.greynoise_key"}
    query   = args["query"]
    size    = int(args.get("size", 10))
    params  = urllib.parse.urlencode({"query": query, "size": size})
    url     = f"https://api.greynoise.io/v2/experimental/gnql?{params}"
    headers = {"key": key, "Accept": "application/json", "User-Agent": "mcp-greynoise/1.0"}
    req     = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read().decode())
    return {
        "query":   query,
        "count":   data.get("count"),
        "message": data.get("message"),
        "results": [
            {
                "ip":             d.get("ip"),
                "classification": d.get("classification"),
                "name":           d.get("name"),
                "tags":           d.get("tags", []),
                "last_seen":      d.get("last_seen"),
            }
            for d in data.get("data", [])
        ],
    }


HANDLERS = {
    "greynoise_ip":       handle_greynoise_ip,
    "greynoise_ip_quick": handle_greynoise_ip_quick,
    "greynoise_riot":     handle_greynoise_riot,
    "greynoise_search":   handle_greynoise_search,
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
                "serverInfo": {"name": "greynoise-mcp", "version": "1.0.0"},
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
