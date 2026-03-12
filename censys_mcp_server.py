#!/usr/bin/env python3
"""
MCP server for Censys — internet-wide scanning with rich service/cert detail.
Free API key from https://search.censys.io/account
Save API_ID:API_SECRET to ~/.censys_key  (one line, colon-separated)
"""

import sys
import json
import os
import urllib.request
import urllib.parse
import base64


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
    path = os.path.expanduser("~/.censys_key")
    if not os.path.exists(path):
        raise RuntimeError("Censys credentials not found. Save 'API_ID:API_SECRET' to ~/.censys_key")
    with open(path) as f:
        return f.read().strip()

def auth_header():
    creds   = load_key()
    encoded = base64.b64encode(creds.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}

BASE = "https://search.censys.io/api/v2"

def censys_get(path, params=None):
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {**auth_header(), "Accept": "application/json", "User-Agent": "mcp-censys/1.0"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def censys_post(path, body):
    url     = BASE + path
    data    = json.dumps(body).encode()
    headers = {**auth_header(), "Content-Type": "application/json",
               "Accept": "application/json", "User-Agent": "mcp-censys/1.0"}
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "censys_search_hosts",
        "description": "Search Censys for hosts matching a query. Returns IPs, ports, services, ASN, location. Query examples: 'services.port=8080', 'ip:1.1.1.0/24', 'autonomous_system.name=Orange'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":    {"type": "string",  "description": "Censys search query (e.g. 'services.port=22 and location.country_code=ES')"},
                "per_page": {"type": "integer", "description": "Results per page (default 25, max 100)"},
                "cursor":   {"type": "string",  "description": "Pagination cursor from previous result"},
                "fields":   {"type": "array",   "items": {"type": "string"}, "description": "Fields to return (e.g. ['ip','services.port','location'])"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "censys_host",
        "description": "Get full details for a specific IP: all open services, banners, TLS certs, geolocation, ASN, vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 or IPv6 address"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "censys_host_diff",
        "description": "Compare two snapshots of a host to see what changed (services added/removed, cert changes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address"},
                "at_time": {"type": "string", "description": "ISO timestamp for historical snapshot (e.g. '2024-01-01T00:00:00Z')"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "censys_search_certs",
        "description": "Search Censys certificate index. Find certs by domain, org, fingerprint, issuer, validity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":    {"type": "string",  "description": "Certificate search query (e.g. 'parsed.subject.organization=Orange')"},
                "per_page": {"type": "integer", "description": "Results per page (default 25, max 100)"},
                "fields":   {"type": "array",   "items": {"type": "string"}, "description": "Fields to return"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "censys_view_cert",
        "description": "Get full details of a certificate by SHA-256 fingerprint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fingerprint": {"type": "string", "description": "SHA-256 certificate fingerprint"},
            },
            "required": ["fingerprint"],
        },
    },
    {
        "name": "censys_bulk_hosts",
        "description": "Get summary data for multiple IP addresses at once (up to 100).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ips": {"type": "array", "items": {"type": "string"}, "description": "List of IPv4 addresses"},
            },
            "required": ["ips"],
        },
    },
    {
        "name": "censys_aggregate",
        "description": "Aggregate Censys host search results by a field (e.g. count by country, ASN, port, software).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":      {"type": "string", "description": "Base search query"},
                "field":      {"type": "string", "description": "Field to aggregate by (e.g. 'location.country', 'autonomous_system.asn', 'services.port')"},
                "num_buckets":{"type": "integer","description": "Number of buckets to return (default 10, max 100)"},
            },
            "required": ["query", "field"],
        },
    },
    {
        "name": "censys_account",
        "description": "Check Censys account info and remaining API quota.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def _fmt_service(s):
    return {
        "port":            s.get("port"),
        "transport":       s.get("transport_protocol"),
        "service_name":    s.get("service_name"),
        "extended_service":s.get("extended_service_name"),
        "banner":          (s.get("banner") or "")[:200] or None,
        "software":        [
            f"{sw.get('product','')} {sw.get('version','')}".strip()
            for sw in (s.get("software") or [])[:5]
        ],
        "tls": {
            "cert_cn":    (((s.get("tls") or {}).get("certificates") or {}).get("leaf_data") or {}).get("subject_dn"),
            "issuer":     (((s.get("tls") or {}).get("certificates") or {}).get("leaf_data") or {}).get("issuer_dn"),
            "not_after":  ((((s.get("tls") or {}).get("certificates") or {}).get("leaf_data") or {}).get("validity") or {}).get("end"),
        } if s.get("tls") else None,
    }

def _fmt_host(h):
    return {
        "ip":         h.get("ip"),
        "last_seen":  (h.get("last_updated_at") or "")[:10] or None,
        "asn":        (h.get("autonomous_system") or {}).get("asn"),
        "asn_name":   (h.get("autonomous_system") or {}).get("name"),
        "bgp_prefix": (h.get("autonomous_system") or {}).get("bgp_prefix"),
        "country":    (h.get("location") or {}).get("country_code"),
        "city":       (h.get("location") or {}).get("city"),
        "labels":     h.get("labels", []),
        "services":   [_fmt_service(s) for s in (h.get("services") or [])[:20]],
        "open_ports": sorted(set(s.get("port") for s in (h.get("services") or []) if s.get("port"))),
    }


def handle_censys_search_hosts(args):
    body = {
        "q":        args["query"],
        "per_page": min(int(args.get("per_page", 25)), 100),
    }
    if "cursor" in args:
        body["cursor"] = args["cursor"]
    if "fields" in args:
        body["fields"] = args["fields"]
    data   = censys_post("/hosts/search", body)
    result = data.get("result", {})
    hits   = result.get("hits", [])
    return {
        "query":     args["query"],
        "total":     result.get("total"),
        "next_cursor": result.get("links", {}).get("next"),
        "count":     len(hits),
        "hosts":     [_fmt_host(h) for h in hits],
    }


def handle_censys_host(args):
    ip   = args["ip"]
    data = censys_get(f"/hosts/{ip}")
    h    = data.get("result", {})
    return _fmt_host(h)


def handle_censys_host_diff(args):
    ip  = args["ip"]
    params = {}
    if "at_time" in args:
        params["at_time"] = args["at_time"]
    data = censys_get(f"/hosts/{ip}/diff", params or None)
    return data.get("result", data)


def handle_censys_search_certs(args):
    body = {
        "q":        args["query"],
        "per_page": min(int(args.get("per_page", 25)), 100),
    }
    if "fields" in args:
        body["fields"] = args["fields"]
    data   = censys_post("/certificates/search", body)
    result = data.get("result", {})
    hits   = result.get("hits", [])
    return {
        "query": args["query"],
        "total": result.get("total"),
        "count": len(hits),
        "certs": [
            {
                "fingerprint":  c.get("fingerprint_sha256") or c.get("fingerprint"),
                "subject_dn":   (c.get("parsed") or {}).get("subject_dn"),
                "issuer_dn":    (c.get("parsed") or {}).get("issuer_dn"),
                "not_before":   ((c.get("parsed") or {}).get("validity") or {}).get("start", "")[:10] or None,
                "not_after":    ((c.get("parsed") or {}).get("validity") or {}).get("end", "")[:10] or None,
                "names":        (c.get("parsed") or {}).get("names", [])[:10],
            }
            for c in hits
        ],
    }


def handle_censys_view_cert(args):
    fp   = args["fingerprint"]
    data = censys_get(f"/certificates/{fp}")
    c    = data.get("result", {})
    return {
        "fingerprint":  fp,
        "subject_dn":   (c.get("parsed") or {}).get("subject_dn"),
        "issuer_dn":    (c.get("parsed") or {}).get("issuer_dn"),
        "not_before":   ((c.get("parsed") or {}).get("validity") or {}).get("start", "")[:10] or None,
        "not_after":    ((c.get("parsed") or {}).get("validity") or {}).get("end", "")[:10] or None,
        "names":        (c.get("parsed") or {}).get("names", []),
        "subject":      (c.get("parsed") or {}).get("subject", {}),
        "issuer":       (c.get("parsed") or {}).get("issuer", {}),
        "key_algorithm":(c.get("parsed") or {}).get("subject_key_info", {}).get("key_algorithm", {}).get("name"),
        "key_size":     (c.get("parsed") or {}).get("subject_key_info", {}).get("rsa_public_key", {}).get("length"),
    }


def handle_censys_bulk_hosts(args):
    ips  = args["ips"][:100]
    data = censys_post("/hosts/bulk", {"ips": ips})
    results = data.get("result", {}).get("hosts", {})
    return {
        "count":  len(results),
        "hosts":  {ip: _fmt_host(h) for ip, h in results.items()},
    }


def handle_censys_aggregate(args):
    body = {
        "q":           args["query"],
        "field":       args["field"],
        "num_buckets": min(int(args.get("num_buckets", 10)), 100),
    }
    data    = censys_post("/hosts/aggregate", body)
    result  = data.get("result", {})
    buckets = result.get("buckets", [])
    return {
        "query":   args["query"],
        "field":   args["field"],
        "total":   result.get("total"),
        "buckets": buckets,
    }


def handle_censys_account(args):
    # v1 endpoint for account info
    url  = "https://search.censys.io/api/v1/account"
    headers = {**auth_header(), "Accept": "application/json", "User-Agent": "mcp-censys/1.0"}
    req  = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode())
    return {
        "login":    data.get("login"),
        "email":    data.get("email"),
        "quota": {
            "used":       data.get("quota", {}).get("used"),
            "allowance":  data.get("quota", {}).get("allowance"),
            "resets_at":  data.get("quota", {}).get("resets_at"),
        },
    }


HANDLERS = {
    "censys_search_hosts": handle_censys_search_hosts,
    "censys_host":         handle_censys_host,
    "censys_host_diff":    handle_censys_host_diff,
    "censys_search_certs": handle_censys_search_certs,
    "censys_view_cert":    handle_censys_view_cert,
    "censys_bulk_hosts":   handle_censys_bulk_hosts,
    "censys_aggregate":    handle_censys_aggregate,
    "censys_account":      handle_censys_account,
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
                "serverInfo": {"name": "censys-mcp", "version": "1.0.0"},
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
