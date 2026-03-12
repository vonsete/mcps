#!/usr/bin/env python3
"""
MCP server for SecurityTrails — DNS history, subdomain enumeration, WHOIS history.
Free tier: 50 requests/month.
API key from https://securitytrails.com/corp/api
Save to ~/.securitytrails_key
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
    path = os.path.expanduser("~/.securitytrails_key")
    if not os.path.exists(path):
        raise RuntimeError("SecurityTrails API key not found. Save it to ~/.securitytrails_key")
    with open(path) as f:
        return f.read().strip()

def st_get(path, params=None):
    key = load_key()
    url = f"https://api.securitytrails.com/v1{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "APIKEY":     key,
        "Accept":     "application/json",
        "User-Agent": "mcp-securitytrails/1.0",
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def st_post(path, body):
    key  = load_key()
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"https://api.securitytrails.com/v1{path}",
        data=data,
        headers={
            "APIKEY":       key,
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "User-Agent":   "mcp-securitytrails/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "st_domain_info",
        "description": "Get general information about a domain: current DNS records, WHOIS, hosting provider, subdomains count.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name (e.g. 'example.com')"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "st_subdomains",
        "description": "List all known subdomains for a domain discovered by SecurityTrails.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":   {"type": "string",  "description": "Root domain"},
                "children": {"type": "boolean", "description": "Include child subdomains (default false)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "st_dns_history",
        "description": "Get historical DNS records for a domain. Shows how DNS has changed over time.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":      {"type": "string", "description": "Domain name"},
                "record_type": {"type": "string", "description": "Record type: a, aaaa, mx, ns, txt, soa, cname (default: a)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "st_whois_history",
        "description": "Get WHOIS history for a domain — registrant changes, nameserver changes, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name"},
                "page":   {"type": "integer", "description": "Page number (default 1)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "st_ip_neighbors",
        "description": "Find all domains hosted on the same IP or neighboring IPs (same /24 subnet).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "st_associated_domains",
        "description": "Find domains associated with a domain (same registrant, NS, MX, or IP).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name"},
                "page":   {"type": "integer", "description": "Page number (default 1)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "st_search_domains",
        "description": "Search domains by filter: IPv4, hostname keyword, MX host, NS host, WHOIS email/org, or keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ipv4":    {"type": "string", "description": "Filter by IP address"},
                "hostname":{"type": "string", "description": "Filter by hostname keyword"},
                "mx":      {"type": "string", "description": "Filter by MX server"},
                "ns":      {"type": "string", "description": "Filter by nameserver"},
                "whois_email": {"type": "string", "description": "Filter by WHOIS email"},
                "whois_org":   {"type": "string", "description": "Filter by WHOIS organization"},
                "keyword":     {"type": "string", "description": "Search keyword"},
                "page":        {"type": "integer","description": "Page number (default 1)"},
            },
        },
    },
    {
        "name": "st_ip_info",
        "description": "Get information about an IP: PTR records, open ports (via Shodan integration), hosting info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "st_ping",
        "description": "Check SecurityTrails API connectivity and remaining quota.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def handle_st_domain_info(args):
    domain = args["domain"]
    data   = st_get(f"/domain/{domain}")
    cur    = data.get("current_dns", {})
    return {
        "domain":        domain,
        "hostname":      data.get("hostname"),
        "alexa_rank":    data.get("alexa_rank"),
        "apex_domain":   data.get("apex_domain"),
        "subdomain_count": data.get("subdomain_count"),
        "current_dns": {
            "a":     [v.get("ip")     for v in cur.get("a",     {}).get("values", [])],
            "aaaa":  [v.get("ipv6")   for v in cur.get("aaaa",  {}).get("values", [])],
            "mx":    [v.get("hostname")for v in cur.get("mx",    {}).get("values", [])],
            "ns":    [v.get("nameserver") for v in cur.get("ns", {}).get("values", [])],
            "txt":   [v.get("value")  for v in cur.get("txt",   {}).get("values", [])],
        },
        "whois": {
            "registrar":   data.get("registrar_name"),
            "created":     (data.get("whois", {}).get("createdDate") or "")[:10] or None,
            "expires":     (data.get("whois", {}).get("expiresDate") or "")[:10] or None,
            "registrant":  data.get("whois", {}).get("registrant", {}),
            "nameservers": data.get("whois", {}).get("nameServers", []),
        },
    }


def handle_st_subdomains(args):
    domain   = args["domain"]
    children = bool(args.get("children", False))
    params   = {"children_only": str(children).lower()}
    data     = st_get(f"/domain/{domain}/subdomains", params)
    subs     = data.get("subdomains", [])
    return {
        "domain":     domain,
        "count":      data.get("subdomain_count", len(subs)),
        "subdomains": sorted([f"{s}.{domain}" for s in subs]),
    }


def handle_st_dns_history(args):
    domain      = args["domain"]
    record_type = args.get("record_type", "a").lower()
    data        = st_get(f"/history/{domain}/dns/{record_type}")
    records     = data.get("records", [])
    return {
        "domain":      domain,
        "record_type": record_type,
        "count":       len(records),
        "history": [
            {
                "first_seen":  r.get("first_seen"),
                "last_seen":   r.get("last_seen"),
                "organizations": r.get("organizations", []),
                "values":      r.get("values", []),
            }
            for r in records
        ],
    }


def handle_st_whois_history(args):
    domain = args["domain"]
    page   = int(args.get("page", 1))
    data   = st_get(f"/history/{domain}/whois", {"page": page})
    items  = data.get("result", {}).get("items", [])
    return {
        "domain": domain,
        "page":   page,
        "count":  len(items),
        "history": [
            {
                "started":    (i.get("started") or "")[:10] or None,
                "ended":      (i.get("ended") or "")[:10] or None,
                "registrar":  i.get("registrar", {}).get("name"),
                "registrant": i.get("contacts", [{}])[0].get("organization") if i.get("contacts") else None,
                "email":      i.get("contacts", [{}])[0].get("email") if i.get("contacts") else None,
                "nameservers":i.get("nameservers", []),
            }
            for i in items
        ],
    }


def handle_st_ip_neighbors(args):
    ip   = args["ip"]
    data = st_get(f"/ips/nearby/{ip}")
    blocks = data.get("blocks", [])
    result = []
    for b in blocks:
        for site in b.get("sites", []):
            result.append({
                "ip":      b.get("ip"),
                "domain":  site,
            })
    return {
        "ip":      ip,
        "count":   len(result),
        "neighbors": result[:100],
    }


def handle_st_associated_domains(args):
    domain = args["domain"]
    page   = int(args.get("page", 1))
    data   = st_get(f"/domain/{domain}/associated", {"page": page})
    items  = data.get("records", [])
    return {
        "domain":  domain,
        "page":    page,
        "count":   data.get("record_count", len(items)),
        "domains": [
            {
                "hostname":   i.get("hostname"),
                "alexa_rank": i.get("alexa_rank"),
                "whois_org":  (i.get("whois") or {}).get("registrant_org"),
                "computed": {
                    "company_results": (i.get("computed") or {}).get("company_results"),
                },
            }
            for i in items
        ],
    }


def handle_st_search_domains(args):
    page    = int(args.get("page", 1))
    filters = {}
    for f in ["ipv4", "hostname", "mx", "ns", "whois_email", "whois_org", "keyword"]:
        if f in args:
            filters[f] = args[f]
    body = {"filter": filters}
    data = st_post(f"/domains/list?page={page}", body)
    items = data.get("records", [])
    return {
        "total":   data.get("record_count"),
        "page":    page,
        "count":   len(items),
        "domains": [
            {
                "hostname":    i.get("hostname"),
                "alexa_rank":  i.get("alexa_rank"),
                "whois_org":   (i.get("whois") or {}).get("registrant_org"),
            }
            for i in items
        ],
    }


def handle_st_ip_info(args):
    ip   = args["ip"]
    data = st_get(f"/ips/{ip}")
    return {
        "ip":          ip,
        "ptr":         data.get("ptr"),
        "asn":         data.get("asn"),
        "asn_name":    data.get("asn_name"),
        "country":     data.get("country_code"),
        "city":        data.get("city"),
        "open_ports":  data.get("ports", []),
        "updated_at":  (data.get("updated_at") or "")[:10] or None,
    }


def handle_st_ping(args):
    data = st_get("/ping")
    return {"status": "ok", "message": data.get("message"), "endpoint": "securitytrails.com"}


HANDLERS = {
    "st_domain_info":     handle_st_domain_info,
    "st_subdomains":      handle_st_subdomains,
    "st_dns_history":     handle_st_dns_history,
    "st_whois_history":   handle_st_whois_history,
    "st_ip_neighbors":    handle_st_ip_neighbors,
    "st_associated_domains": handle_st_associated_domains,
    "st_search_domains":  handle_st_search_domains,
    "st_ip_info":         handle_st_ip_info,
    "st_ping":            handle_st_ping,
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
                "serverInfo": {"name": "securitytrails-mcp", "version": "1.0.0"},
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
