#!/usr/bin/env python3
"""
MCP server for BGP/ASN lookups.
Uses RIPE NCC Stat API (stat.ripe.net) — no API key required.
"""

import sys
import json
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


def ripe_get(endpoint, params):
    resp = requests.get(
        f"https://stat.ripe.net/data/{endpoint}/data.json",
        params=params,
        headers={"Accept": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("data", {})


def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "bgp_lookup_ip",
        "description": "Get BGP/ASN information for an IP address: ASN, prefix, country, RIR and holder.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up (e.g. '8.8.8.8')"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "bgp_lookup_asn",
        "description": "Get details about an ASN: name, description, prefixes announced, abuse contact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asn": {"type": "integer", "description": "ASN number (e.g. 3352 for Telefonica)"},
            },
            "required": ["asn"],
        },
    },
    {
        "name": "bgp_asn_prefixes",
        "description": "Get all IPv4 and IPv6 prefixes announced by an ASN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asn": {"type": "integer", "description": "ASN number"},
            },
            "required": ["asn"],
        },
    },
    {
        "name": "bgp_asn_peers",
        "description": "Get BGP neighbours/peers of an ASN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asn": {"type": "integer", "description": "ASN number"},
            },
            "required": ["asn"],
        },
    },
    {
        "name": "bgp_lookup_prefix",
        "description": "Get BGP details for a specific prefix (e.g. '8.8.8.0/24').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prefix": {"type": "string", "description": "IP prefix in CIDR notation (e.g. '8.8.8.0/24')"},
            },
            "required": ["prefix"],
        },
    },
    {
        "name": "bgp_search_asn",
        "description": "Search for ASNs by name or description (e.g. 'Telefonica', 'Orange').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term (company name, ISP, etc.)"},
            },
            "required": ["query"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_lookup_ip(args):
    ip = args.get("ip")

    # Prefix overview
    prefix_data = ripe_get("prefix-overview", {"resource": ip})
    # Network info
    network_data = ripe_get("network-info", {"resource": ip})

    asns = prefix_data.get("asns", [])
    return {
        "ip":       ip,
        "prefix":   network_data.get("prefix"),
        "asns": [
            {"asn": a.get("asn"), "holder": a.get("holder")}
            for a in asns
        ],
        "announced": prefix_data.get("announced"),
        "block":     prefix_data.get("block", {}).get("desc"),
    }


def handle_lookup_asn(args):
    asn  = args.get("asn")
    data = ripe_get("as-overview", {"resource": f"AS{asn}"})
    abuse = ripe_get("abuse-contact-finder", {"resource": f"AS{asn}"})
    contacts = abuse.get("abuse_contacts", [])
    return {
        "asn":          asn,
        "holder":       data.get("holder"),
        "announced":    data.get("announced"),
        "block":        data.get("block", {}).get("desc"),
        "abuse_contacts": contacts,
    }


def handle_asn_prefixes(args):
    asn  = args.get("asn")
    data = ripe_get("announced-prefixes", {"resource": f"AS{asn}"})
    prefixes = data.get("prefixes", [])
    ipv4 = [p for p in prefixes if ":" not in p.get("prefix", "")]
    ipv6 = [p for p in prefixes if ":" in p.get("prefix", "")]
    return {
        "asn":        asn,
        "total_ipv4": len(ipv4),
        "total_ipv6": len(ipv6),
        "ipv4":       [{"prefix": p["prefix"], "timelines": len(p.get("timelines", []))} for p in ipv4[:20]],
        "ipv6":       [{"prefix": p["prefix"]} for p in ipv6[:10]],
    }


def handle_asn_peers(args):
    asn  = args.get("asn")
    data = ripe_get("peers", {"resource": f"AS{asn}"})
    peers = data.get("peers", [])
    return {
        "asn":        asn,
        "total_peers": len(peers),
        "peers": [
            {"asn": p.get("asn"), "power": p.get("power")}
            for p in sorted(peers, key=lambda x: x.get("power", 0), reverse=True)[:20]
        ],
    }


def handle_lookup_prefix(args):
    prefix = args.get("prefix")
    data   = ripe_get("prefix-overview", {"resource": prefix})
    return {
        "prefix":    data.get("resource"),
        "announced": data.get("announced"),
        "asns": [
            {"asn": a.get("asn"), "holder": a.get("holder")}
            for a in data.get("asns", [])
        ],
        "block": data.get("block", {}).get("desc"),
    }


def handle_search_asn(args):
    query = args.get("query")
    data  = ripe_get("as-names", {"resource": query})
    # as-names returns a dict of ASN -> name
    names = data.get("names", {})
    results = [
        {"asn": int(asn.replace("AS", "")), "name": name}
        for asn, name in names.items()
        if query.lower() in name.lower()
    ]
    return results[:15]


HANDLERS = {
    "bgp_lookup_ip":     handle_lookup_ip,
    "bgp_lookup_asn":    handle_lookup_asn,
    "bgp_asn_prefixes":  handle_asn_prefixes,
    "bgp_asn_peers":     handle_asn_peers,
    "bgp_lookup_prefix": handle_lookup_prefix,
    "bgp_search_asn":    handle_search_asn,
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
                "serverInfo": {"name": "bgp-mcp", "version": "2.0.0"},
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
