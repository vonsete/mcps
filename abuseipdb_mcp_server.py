#!/usr/bin/env python3
"""
MCP server for AbuseIPDB API v2.
API key loaded from ABUSEIPDB_API_KEY env var or ~/.abuseipdb_key file.
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
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        key_file = os.path.expanduser("~/.abuseipdb_key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ABUSEIPDB_API_KEY="):
                        key = line.split("=", 1)[1].strip()
                    elif line and not line.startswith("#"):
                        key = line
    if not key:
        raise RuntimeError("AbuseIPDB API key not found. Set ABUSEIPDB_API_KEY or create ~/.abuseipdb_key")
    return key


def abuse_get(path, params=None):
    key  = get_api_key()
    resp = requests.get(
        f"https://api.abuseipdb.com/api/v2/{path}",
        headers={"Key": key, "Accept": "application/json"},
        params=params,
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
        "name": "abuse_check_ip",
        "description": "Check an IP address against AbuseIPDB. Returns abuse confidence score, reports and geolocation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check (e.g. '8.8.8.8')"},
                "max_age_days": {"type": "integer", "description": "Only consider reports within this many days (default 30, max 365)"},
                "verbose": {"type": "boolean", "description": "Include last reports details (default false)"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "abuse_check_cidr",
        "description": "Check a CIDR block against AbuseIPDB. Returns most reported IPs in the range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cidr": {"type": "string", "description": "CIDR block to check (e.g. '192.168.0.0/24')"},
                "max_age_days": {"type": "integer", "description": "Only consider reports within this many days (default 30)"},
            },
            "required": ["cidr"],
        },
    },
    {
        "name": "abuse_report_ip",
        "description": "Report an abusive IP address to AbuseIPDB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to report"},
                "categories": {"type": "string", "description": "Comma-separated category IDs (e.g. '18,22' for Brute-Force,SSH). See https://www.abuseipdb.com/categories"},
                "comment": {"type": "string", "description": "Description of the abuse"},
            },
            "required": ["ip", "categories"],
        },
    },
    {
        "name": "abuse_blacklist",
        "description": "Get a list of the most reported IPs in the last 24h from AbuseIPDB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "confidence_minimum": {"type": "integer", "description": "Minimum abuse confidence score 25-100 (default 100)"},
                "limit": {"type": "integer", "description": "Number of IPs to return (default 25, max 10000)"},
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_check_ip(args):
    ip          = args.get("ip")
    max_age     = args.get("max_age_days", 30)
    verbose     = args.get("verbose", False)
    params      = {"ipAddress": ip, "maxAgeInDays": max_age}
    if verbose:
        params["verbose"] = True
    data = abuse_get("check", params)
    d    = data.get("data", {})
    result = {
        "ip":                   d.get("ipAddress"),
        "abuse_confidence":     d.get("abuseConfidenceScore"),
        "total_reports":        d.get("totalReports"),
        "distinct_users":       d.get("numDistinctUsers"),
        "last_reported":        d.get("lastReportedAt"),
        "country":              d.get("countryCode"),
        "isp":                  d.get("isp"),
        "domain":               d.get("domain"),
        "is_tor":               d.get("isTor"),
        "is_public":            d.get("isPublic"),
        "usage_type":           d.get("usageType"),
        "whitelisted":          d.get("isWhitelisted"),
    }
    if verbose and d.get("reports"):
        result["recent_reports"] = [
            {
                "reported_at": r.get("reportedAt"),
                "comment":     r.get("comment"),
                "categories":  r.get("categories"),
            }
            for r in d.get("reports", [])[:10]
        ]
    return result


def handle_check_cidr(args):
    cidr    = args.get("cidr")
    max_age = args.get("max_age_days", 30)
    data    = abuse_get("check-block", {"network": cidr, "maxAgeInDays": max_age})
    d       = data.get("data", {})
    return {
        "network":       d.get("networkAddress"),
        "netmask":       d.get("netmask"),
        "reported_ips":  [
            {
                "ip":               r.get("ipAddress"),
                "abuse_confidence": r.get("abuseConfidenceScore"),
                "total_reports":    r.get("totalReports"),
                "last_reported":    r.get("lastReportedAt"),
                "country":          r.get("countryCode"),
                "isp":              r.get("isp"),
            }
            for r in d.get("reportedAddress", [])
        ],
    }


def handle_report_ip(args):
    key  = get_api_key()
    resp = requests.post(
        "https://api.abuseipdb.com/api/v2/report",
        headers={"Key": key, "Accept": "application/json"},
        data={
            "ip":         args.get("ip"),
            "categories": args.get("categories"),
            "comment":    args.get("comment", ""),
        },
        timeout=15,
    )
    resp.raise_for_status()
    d = resp.json().get("data", {})
    return {
        "ip":               d.get("ipAddress"),
        "abuse_confidence": d.get("abuseConfidenceScore"),
    }


def handle_blacklist(args):
    confidence = args.get("confidence_minimum", 100)
    limit      = args.get("limit", 25)
    data       = abuse_get("blacklist", {"confidenceMinimum": confidence, "limit": limit})
    return [
        {
            "ip":               e.get("ipAddress"),
            "abuse_confidence": e.get("abuseConfidenceScore"),
            "last_reported":    e.get("lastReportedAt"),
            "country":          e.get("countryCode"),
            "isp":              e.get("isp"),
        }
        for e in data.get("data", [])
    ]


HANDLERS = {
    "abuse_check_ip":   handle_check_ip,
    "abuse_check_cidr": handle_check_cidr,
    "abuse_report_ip":  handle_report_ip,
    "abuse_blacklist":  handle_blacklist,
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
                "serverInfo": {"name": "abuseipdb-mcp", "version": "1.0.0"},
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
