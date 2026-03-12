#!/usr/bin/env python3
"""
MCP server for Shodan API.
API key loaded from SHODAN_API_KEY env var or ~/.shodan_key file.
"""

import sys
import json
import os
import requests


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


def get_api_key():
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        key_file = os.path.expanduser("~/.shodan_key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SHODAN_API_KEY="):
                        key = line.split("=", 1)[1].strip()
                    elif line and not line.startswith("#"):
                        key = line
    if not key:
        raise RuntimeError("Shodan API key not found. Set SHODAN_API_KEY or create ~/.shodan_key")
    return key


def shodan_get(path, params=None):
    key = get_api_key()
    p = {"key": key}
    if params:
        p.update(params)
    resp = requests.get(
        f"https://api.shodan.io/{path}",
        params=p,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "shodan_search",
        "description": "Search Shodan for hosts matching a query. Returns IPs, ports, banners and metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Shodan search query (e.g. 'apache city:Madrid', 'port:22 country:ES', 'org:\"Telefonica\"')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10, max 100).",
                },
                "fields": {
                    "type": "string",
                    "description": "Comma-separated fields to return (e.g. 'ip_str,port,org,hostnames'). Default: all.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "shodan_host",
        "description": "Get all available information about a specific IP address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address to look up (e.g. '8.8.8.8')",
                },
                "history": {
                    "type": "boolean",
                    "description": "Include historical data (default false).",
                },
            },
            "required": ["ip"],
        },
    },
    {
        "name": "shodan_count",
        "description": "Count the number of results for a Shodan query without consuming query credits.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Shodan search query",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "shodan_dns_resolve",
        "description": "Resolve hostnames to IP addresses using Shodan DNS.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostnames": {
                    "type": "string",
                    "description": "Comma-separated hostnames to resolve (e.g. 'google.com,facebook.com')",
                },
            },
            "required": ["hostnames"],
        },
    },
    {
        "name": "shodan_reverse_dns",
        "description": "Look up hostnames for a list of IP addresses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ips": {
                    "type": "string",
                    "description": "Comma-separated IP addresses (e.g. '8.8.8.8,1.1.1.1')",
                },
            },
            "required": ["ips"],
        },
    },
    {
        "name": "shodan_my_ip",
        "description": "Get your current public IP address as seen by Shodan.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "shodan_account",
        "description": "Get your Shodan account info and remaining query credits.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_search(args):
    query       = args.get("query")
    max_results = min(args.get("max_results", 10), 100)
    fields      = args.get("fields")

    params = {"query": query, "page": 1}
    if fields:
        params["fields"] = fields

    data = shodan_get("shodan/host/search", params)

    results = []
    for match in data.get("matches", [])[:max_results]:
        entry = {
            "ip":        match.get("ip_str"),
            "port":      match.get("port"),
            "transport": match.get("transport"),
            "org":       match.get("org"),
            "country":   match.get("location", {}).get("country_name"),
            "city":      match.get("location", {}).get("city"),
            "hostnames": match.get("hostnames", []),
            "domains":   match.get("domains", []),
            "product":   match.get("product"),
            "version":   match.get("version"),
            "cpe":       match.get("cpe23", []),
            "vulns":     list(match.get("vulns", {}).keys()),
            "timestamp": match.get("timestamp"),
            "banner":    (match.get("data") or "")[:300],
        }
        results.append(entry)

    return {
        "total":   data.get("total", 0),
        "showing": len(results),
        "results": results,
    }


def handle_host(args):
    ip      = args.get("ip")
    history = args.get("history", False)
    params  = {}
    if history:
        params["history"] = "true"
    data = shodan_get(f"shodan/host/{ip}", params)

    return {
        "ip":           data.get("ip_str"),
        "org":          data.get("org"),
        "isp":          data.get("isp"),
        "asn":          data.get("asn"),
        "country":      data.get("country_name"),
        "city":         data.get("city"),
        "hostnames":    data.get("hostnames", []),
        "domains":      data.get("domains", []),
        "tags":         data.get("tags", []),
        "vulns":        list(data.get("vulns", {}).keys()),
        "ports":        data.get("ports", []),
        "last_update":  data.get("last_update"),
        "services": [
            {
                "port":      s.get("port"),
                "transport": s.get("transport"),
                "product":   s.get("product"),
                "version":   s.get("version"),
                "cpe":       s.get("cpe23", []),
                "banner":    (s.get("data") or "")[:200],
            }
            for s in data.get("data", [])
        ],
    }


def handle_count(args):
    data = shodan_get("shodan/host/count", {"query": args.get("query")})
    return {"total": data.get("total", 0)}


def handle_dns_resolve(args):
    hostnames = args.get("hostnames")
    return shodan_get("dns/resolve", {"hostnames": hostnames})


def handle_reverse_dns(args):
    ips = args.get("ips")
    return shodan_get("dns/reverse", {"ips": ips})


def handle_my_ip(args):
    key  = get_api_key()
    resp = requests.get("https://api.shodan.io/tools/myip", params={"key": key}, timeout=10)
    resp.raise_for_status()
    return {"ip": resp.json()}


def handle_account(args):
    return shodan_get("api-info")


HANDLERS = {
    "shodan_search":      handle_search,
    "shodan_host":        handle_host,
    "shodan_count":       handle_count,
    "shodan_dns_resolve": handle_dns_resolve,
    "shodan_reverse_dns": handle_reverse_dns,
    "shodan_my_ip":       handle_my_ip,
    "shodan_account":     handle_account,
}


def handle_call(id, name, args):
    handler = HANDLERS.get(name)
    if not handler:
        error(id, -32601, f"Unknown tool: {name}")
        return
    try:
        result = handler(args)
        respond(id, text_result(result))
    except requests.HTTPError as e:
        respond(id, {"content": [{"type": "text", "text": f"[HTTP error]: {e} — {e.response.text[:300]}"}], "isError": True})
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
                "serverInfo": {"name": "shodan-mcp", "version": "1.0.0"},
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
