#!/usr/bin/env python3
"""
MCP server for Cloudflare API.
Reads API token from ~/.cloudflare_key
"""

import sys
import json
import os
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

def load_key():
    path = os.path.expanduser("~/.cloudflare_key")
    with open(path) as f:
        return f.read().strip()

def cf_request(method, path, data=None, params=None):
    token = load_key()
    url = f"https://api.cloudflare.com/client/v4{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "cf_list_zones",
        "description": "List all Cloudflare zones (domains) in your account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Filter by domain name (optional)"},
            },
        },
    },
    {
        "name": "cf_list_dns_records",
        "description": "List DNS records for a Cloudflare zone.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone_id":     {"type": "string", "description": "Zone ID (use cf_list_zones to get it)"},
                "record_type": {"type": "string", "description": "Filter by type: A, AAAA, CNAME, MX, TXT, etc. (optional)"},
                "name":        {"type": "string", "description": "Filter by record name (optional)"},
            },
            "required": ["zone_id"],
        },
    },
    {
        "name": "cf_create_dns_record",
        "description": "Create a new DNS record in a Cloudflare zone.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone_id":  {"type": "string", "description": "Zone ID"},
                "type":     {"type": "string", "description": "Record type: A, AAAA, CNAME, MX, TXT, etc."},
                "name":     {"type": "string", "description": "Record name (e.g. 'www' or '@')"},
                "content":  {"type": "string", "description": "Record content (e.g. IP address or hostname)"},
                "ttl":      {"type": "integer", "description": "TTL in seconds (1 = auto)"},
                "proxied":  {"type": "boolean", "description": "Whether to proxy through Cloudflare (orange cloud)"},
                "priority": {"type": "integer", "description": "Priority (MX records only)"},
            },
            "required": ["zone_id", "type", "name", "content"],
        },
    },
    {
        "name": "cf_delete_dns_record",
        "description": "Delete a DNS record from a Cloudflare zone.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone_id":   {"type": "string", "description": "Zone ID"},
                "record_id": {"type": "string", "description": "DNS record ID (use cf_list_dns_records to get it)"},
            },
            "required": ["zone_id", "record_id"],
        },
    },
    {
        "name": "cf_zone_analytics",
        "description": "Get traffic analytics for a Cloudflare zone (requests, bandwidth, threats, unique visitors).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone_id": {"type": "string", "description": "Zone ID"},
                "since":   {"type": "string", "description": "Start date (ISO 8601, e.g. '-1440' for last 24h in minutes or '2024-01-01T00:00:00Z')"},
                "until":   {"type": "string", "description": "End date (ISO 8601). Omit for now."},
            },
            "required": ["zone_id"],
        },
    },
    {
        "name": "cf_purge_cache",
        "description": "Purge Cloudflare cache for a zone — purge everything or specific URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone_id":  {"type": "string", "description": "Zone ID"},
                "purge_all": {"type": "boolean", "description": "Purge all cached files"},
                "files":    {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of specific URLs to purge (if not purging all)",
                },
            },
            "required": ["zone_id"],
        },
    },
    {
        "name": "cf_list_firewall_rules",
        "description": "List WAF firewall rules for a Cloudflare zone.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone_id": {"type": "string", "description": "Zone ID"},
            },
            "required": ["zone_id"],
        },
    },
    {
        "name": "cf_account_info",
        "description": "Get Cloudflare account information and membership details.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_cf_list_zones(args):
    params = {}
    if args.get("name"):
        params["name"] = args["name"]
    data = cf_request("GET", "/zones", params=params or None)
    zones = data.get("result", [])
    return {
        "total": len(zones),
        "zones": [
            {
                "id":     z["id"],
                "name":   z["name"],
                "status": z["status"],
                "plan":   z.get("plan", {}).get("name"),
                "ns":     z.get("name_servers", []),
            }
            for z in zones
        ],
    }


def handle_cf_list_dns_records(args):
    zone_id = args["zone_id"]
    params  = {}
    if args.get("record_type"):
        params["type"] = args["record_type"]
    if args.get("name"):
        params["name"] = args["name"]
    data    = cf_request("GET", f"/zones/{zone_id}/dns_records", params=params or None)
    records = data.get("result", [])
    return {
        "total": len(records),
        "records": [
            {
                "id":      r["id"],
                "type":    r["type"],
                "name":    r["name"],
                "content": r["content"],
                "ttl":     r["ttl"],
                "proxied": r.get("proxied"),
            }
            for r in records
        ],
    }


def handle_cf_create_dns_record(args):
    zone_id = args["zone_id"]
    body = {
        "type":    args["type"].upper(),
        "name":    args["name"],
        "content": args["content"],
        "ttl":     args.get("ttl", 1),
    }
    if "proxied" in args:
        body["proxied"] = args["proxied"]
    if "priority" in args:
        body["priority"] = args["priority"]
    data = cf_request("POST", f"/zones/{zone_id}/dns_records", data=body)
    r    = data.get("result", {})
    return {"success": data.get("success"), "id": r.get("id"), "name": r.get("name"), "type": r.get("type"), "content": r.get("content")}


def handle_cf_delete_dns_record(args):
    zone_id   = args["zone_id"]
    record_id = args["record_id"]
    data = cf_request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
    return {"success": data.get("success"), "id": data.get("result", {}).get("id")}


def handle_cf_zone_analytics(args):
    zone_id = args["zone_id"]
    params  = {"since": args.get("since", "-1440")}
    if args.get("until"):
        params["until"] = args["until"]
    data    = cf_request("GET", f"/zones/{zone_id}/analytics/dashboard", params=params)
    totals  = data.get("result", {}).get("totals", {})
    return {
        "zone_id":         zone_id,
        "requests_all":    totals.get("requests", {}).get("all"),
        "requests_cached": totals.get("requests", {}).get("cached"),
        "bandwidth_all":   totals.get("bandwidth", {}).get("all"),
        "threats":         totals.get("threats", {}).get("all"),
        "unique_visitors": totals.get("uniques", {}).get("all"),
        "pageviews":       totals.get("pageviews", {}).get("all"),
    }


def handle_cf_purge_cache(args):
    zone_id = args["zone_id"]
    body    = {}
    if args.get("purge_all"):
        body["purge_everything"] = True
    elif args.get("files"):
        body["files"] = args["files"]
    else:
        return {"error": "Provide purge_all=true or a list of files"}
    data = cf_request("POST", f"/zones/{zone_id}/purge_cache", data=body)
    return {"success": data.get("success"), "errors": data.get("errors", [])}


def handle_cf_list_firewall_rules(args):
    zone_id = args["zone_id"]
    data    = cf_request("GET", f"/zones/{zone_id}/firewall/rules")
    rules   = data.get("result", [])
    return {
        "total": len(rules),
        "rules": [
            {
                "id":          r["id"],
                "action":      r["action"],
                "description": r.get("description"),
                "priority":    r.get("priority"),
                "paused":      r.get("paused"),
                "filter":      r.get("filter", {}).get("expression"),
            }
            for r in rules
        ],
    }


def handle_cf_account_info(args):
    data     = cf_request("GET", "/accounts")
    accounts = data.get("result", [])
    return {
        "total": len(accounts),
        "accounts": [
            {
                "id":   a["id"],
                "name": a["name"],
                "type": a.get("type"),
            }
            for a in accounts
        ],
    }


HANDLERS = {
    "cf_list_zones":          handle_cf_list_zones,
    "cf_list_dns_records":    handle_cf_list_dns_records,
    "cf_create_dns_record":   handle_cf_create_dns_record,
    "cf_delete_dns_record":   handle_cf_delete_dns_record,
    "cf_zone_analytics":      handle_cf_zone_analytics,
    "cf_purge_cache":         handle_cf_purge_cache,
    "cf_list_firewall_rules": handle_cf_list_firewall_rules,
    "cf_account_info":        handle_cf_account_info,
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
                "serverInfo": {"name": "cloudflare-mcp", "version": "1.0.0"},
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
