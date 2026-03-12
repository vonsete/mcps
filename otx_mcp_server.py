#!/usr/bin/env python3
"""
MCP server for AlienVault OTX (Open Threat Exchange).
API key from https://otx.alienvault.com — free account.
Save to ~/.otx_key
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
    path = os.path.expanduser("~/.otx_key")
    if not os.path.exists(path):
        raise RuntimeError("OTX API key not found. Save it to ~/.otx_key")
    with open(path) as f:
        return f.read().strip()

def otx_get(path, params=None):
    key = load_key()
    url = f"https://otx.alienvault.com{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "X-OTX-API-KEY": key,
        "User-Agent": "mcp-otx/1.0",
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "otx_ip",
        "description": "Get OTX threat intelligence for an IP address: reputation, pulses, geolocation, malware.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "otx_domain",
        "description": "Get OTX threat intelligence for a domain: pulses, DNS records, malware, URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "otx_hash",
        "description": "Get OTX threat intelligence for a file hash (MD5, SHA1, SHA256).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "File hash (MD5/SHA1/SHA256)"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "otx_url",
        "description": "Get OTX threat intelligence for a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to look up"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "otx_search_pulses",
        "description": "Search OTX pulses (threat reports) by keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":  {"type": "string",  "description": "Search term (e.g. 'ransomware', 'Log4Shell', 'APT28')"},
                "limit":  {"type": "integer", "description": "Number of results (default 10)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "otx_get_pulse",
        "description": "Get full details of an OTX pulse by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pulse_id": {"type": "string", "description": "Pulse ID"},
            },
            "required": ["pulse_id"],
        },
    },
    {
        "name": "otx_subscribed_pulses",
        "description": "Get latest pulses from your OTX subscriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of pulses (default 10)"},
            },
        },
    },
]


def parse_pulse_summary(p):
    return {
        "id":          p.get("id"),
        "name":        p.get("name"),
        "author":      p.get("author_name"),
        "created":     p.get("created")[:10] if p.get("created") else None,
        "modified":    p.get("modified")[:10] if p.get("modified") else None,
        "tlp":         p.get("tlp"),
        "tags":        p.get("tags", [])[:5],
        "adversary":   p.get("adversary"),
        "targeted_countries": p.get("targeted_countries", []),
        "malware_families":   p.get("malware_families", []),
        "attack_ids":  [a.get("display_name") for a in p.get("attack_ids", [])[:3]],
        "indicator_count": p.get("indicator_count"),
    }


def handle_otx_ip(args):
    ip = args["ip"]
    general = otx_get(f"/api/v1/indicators/IPv4/{ip}/general")
    reputa  = otx_get(f"/api/v1/indicators/IPv4/{ip}/reputation")
    pulses  = general.get("pulse_info", {})
    return {
        "ip":           ip,
        "country":      general.get("country_name"),
        "city":         general.get("city"),
        "asn":          general.get("asn"),
        "reputation":   general.get("reputation"),
        "threat_score": reputa.get("threat_score"),
        "pulse_count":  pulses.get("count", 0),
        "pulses":       [parse_pulse_summary(p) for p in pulses.get("pulses", [])[:5]],
        "sections":     general.get("sections", []),
    }


def handle_otx_domain(args):
    domain  = args["domain"]
    general = otx_get(f"/api/v1/indicators/domain/{domain}/general")
    pulses  = general.get("pulse_info", {})
    return {
        "domain":      domain,
        "alexa":       general.get("alexa"),
        "whois":       general.get("whois"),
        "pulse_count": pulses.get("count", 0),
        "pulses":      [parse_pulse_summary(p) for p in pulses.get("pulses", [])[:5]],
        "validation":  general.get("validation", []),
        "sections":    general.get("sections", []),
    }


def handle_otx_hash(args):
    h       = args["hash"]
    general = otx_get(f"/api/v1/indicators/file/{h}/general")
    analysis= otx_get(f"/api/v1/indicators/file/{h}/analysis")
    pulses  = general.get("pulse_info", {})
    av      = analysis.get("analysis", {}).get("plugins", {})
    # Extract AV detections
    detections = {}
    for engine, result in av.items():
        if isinstance(result, dict) and result.get("results", {}).get("detection"):
            detections[engine] = result["results"]["detection"]
    return {
        "hash":           h,
        "pulse_count":    pulses.get("count", 0),
        "pulses":         [parse_pulse_summary(p) for p in pulses.get("pulses", [])[:5]],
        "av_detections":  detections,
        "detection_count": len(detections),
        "file_type":      analysis.get("analysis", {}).get("info", {}).get("results", {}).get("file_type"),
        "file_size":      analysis.get("analysis", {}).get("info", {}).get("results", {}).get("file_size"),
    }


def handle_otx_url(args):
    url     = urllib.parse.quote(args["url"], safe="")
    general = otx_get(f"/api/v1/indicators/url/{url}/general")
    pulses  = general.get("pulse_info", {})
    return {
        "url":         args["url"],
        "pulse_count": pulses.get("count", 0),
        "pulses":      [parse_pulse_summary(p) for p in pulses.get("pulses", [])[:5]],
        "domain":      general.get("domain"),
        "hostname":    general.get("hostname"),
        "result":      general.get("result"),
        "sections":    general.get("sections", []),
    }


def handle_otx_search_pulses(args):
    query = args["query"]
    limit = int(args.get("limit", 10))
    data  = otx_get("/api/v1/search/pulses", params={"q": query, "limit": limit})
    results = data.get("results", [])
    return {
        "query":   query,
        "total":   data.get("count", len(results)),
        "pulses":  [parse_pulse_summary(p) for p in results],
    }


def handle_otx_get_pulse(args):
    pulse_id = args["pulse_id"]
    data = otx_get(f"/api/v1/pulses/{pulse_id}")
    indicators = data.get("indicators", [])
    return {
        "id":          data.get("id"),
        "name":        data.get("name"),
        "description": data.get("description", "")[:500],
        "author":      data.get("author_name"),
        "created":     data.get("created"),
        "modified":    data.get("modified"),
        "tlp":         data.get("tlp"),
        "tags":        data.get("tags", []),
        "adversary":   data.get("adversary"),
        "targeted_countries": data.get("targeted_countries", []),
        "malware_families":   data.get("malware_families", []),
        "attack_ids":  [a.get("display_name") for a in data.get("attack_ids", [])],
        "references":  data.get("references", [])[:5],
        "indicator_count": len(indicators),
        "indicators": [
            {"type": i.get("type"), "indicator": i.get("indicator"), "description": i.get("description")}
            for i in indicators[:20]
        ],
    }


def handle_otx_subscribed_pulses(args):
    limit = int(args.get("limit", 10))
    data  = otx_get("/api/v1/pulses/subscribed", params={"limit": limit})
    results = data.get("results", [])
    return {
        "total":  data.get("count", len(results)),
        "pulses": [parse_pulse_summary(p) for p in results],
    }


HANDLERS = {
    "otx_ip":                handle_otx_ip,
    "otx_domain":            handle_otx_domain,
    "otx_hash":              handle_otx_hash,
    "otx_url":               handle_otx_url,
    "otx_search_pulses":     handle_otx_search_pulses,
    "otx_get_pulse":         handle_otx_get_pulse,
    "otx_subscribed_pulses": handle_otx_subscribed_pulses,
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
                "serverInfo": {"name": "otx-mcp", "version": "1.0.0"},
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
