#!/usr/bin/env python3
"""
MCP server for Maltiverse threat intelligence.
API key from https://maltiverse.com — free account.
Save to ~/.maltiverse_key
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
    path = os.path.expanduser("~/.maltiverse_key")
    if not os.path.exists(path):
        raise RuntimeError("Maltiverse API key not found. Save it to ~/.maltiverse_key")
    with open(path) as f:
        return f.read().strip()

def mv_get(path, params=None):
    key = load_key()
    url = f"https://api.maltiverse.com{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {key}",
        "User-Agent": "mcp-maltiverse/1.0",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "mv_ip",
        "description": "Get Maltiverse threat intelligence for an IP address: classification, tags, blacklist info, geolocation, related URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address to look up"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "mv_domain",
        "description": "Get Maltiverse threat intelligence for a domain: classification, tags, blacklist sources, related IPs and URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "mv_url",
        "description": "Get Maltiverse threat intelligence for a URL: classification, tags, blacklist sources, final URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to look up"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "mv_hash",
        "description": "Get Maltiverse threat intelligence for a file hash (MD5, SHA1, SHA256): classification, AV detections, file type, tags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "File hash (MD5/SHA1/SHA256)"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "mv_search",
        "description": "Search Maltiverse for threat indicators by keyword or tag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":  {"type": "string",  "description": "Search term (e.g. 'ransomware', 'cobalt strike', 'APT28')"},
                "type":   {"type": "string",  "description": "Filter by type: ip, domain, url, sample (optional)"},
                "limit":  {"type": "integer", "description": "Number of results (default 10, max 100)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "mv_feed",
        "description": "Get a Maltiverse threat feed by ID. Common feeds: phishing-url, malware-ip, malware-domain, c2-ip.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "feed_id": {"type": "string", "description": "Feed identifier (e.g. 'phishing-url', 'malware-ip')"},
                "limit":   {"type": "integer", "description": "Number of results (default 20)"},
            },
            "required": ["feed_id"],
        },
    },
]


def _extract_blacklists(data):
    """Extract blacklist source info from Maltiverse response."""
    bls = data.get("blacklist", [])
    return [
        {
            "source":      b.get("source"),
            "description": b.get("description"),
            "first_seen":  b.get("first_seen", "")[:10] if b.get("first_seen") else None,
            "last_seen":   b.get("last_seen", "")[:10] if b.get("last_seen") else None,
        }
        for b in bls[:10]
    ]


def handle_mv_ip(args):
    ip   = args["ip"]
    data = mv_get(f"/ip/{ip}")
    return {
        "ip":              ip,
        "classification":  data.get("classification"),
        "score":           data.get("score"),
        "country":         data.get("country_code"),
        "asn":             data.get("asn_number"),
        "asn_name":        data.get("asn_name"),
        "city":            data.get("city"),
        "tags":            data.get("tag", []),
        "is_cdn":          data.get("is_cdn"),
        "is_tor":          data.get("is_tor"),
        "is_vpn":          data.get("is_vpn"),
        "is_hosting":      data.get("is_hosting"),
        "is_anonymous":    data.get("is_anonymous"),
        "blacklist_count": len(data.get("blacklist", [])),
        "blacklists":      _extract_blacklists(data),
        "url_count":       len(data.get("url", [])),
        "urls_sample":     [u.get("url") for u in data.get("url", [])[:5]],
        "creation_time":   data.get("creation_time", "")[:10] if data.get("creation_time") else None,
        "modification_time": data.get("modification_time", "")[:10] if data.get("modification_time") else None,
    }


def handle_mv_domain(args):
    domain = args["domain"]
    data   = mv_get(f"/hostname/{domain}")
    return {
        "domain":          domain,
        "classification":  data.get("classification"),
        "score":           data.get("score"),
        "resolved_ip":     data.get("resolved_ip"),
        "tags":            data.get("tag", []),
        "is_cdn":          data.get("is_cdn"),
        "is_tor":          data.get("is_tor"),
        "blacklist_count": len(data.get("blacklist", [])),
        "blacklists":      _extract_blacklists(data),
        "url_count":       len(data.get("url", [])),
        "urls_sample":     [u.get("url") for u in data.get("url", [])[:5]],
        "creation_time":   data.get("creation_time", "")[:10] if data.get("creation_time") else None,
        "modification_time": data.get("modification_time", "")[:10] if data.get("modification_time") else None,
    }


def handle_mv_url(args):
    url_enc = urllib.parse.quote(args["url"], safe="")
    data    = mv_get(f"/url/{url_enc}")
    return {
        "url":             args["url"],
        "classification":  data.get("classification"),
        "score":           data.get("score"),
        "hostname":        data.get("hostname"),
        "domain":          data.get("domain"),
        "final_url":       data.get("final_url"),
        "http_code":       data.get("http_code"),
        "content_type":    data.get("content_type"),
        "tags":            data.get("tag", []),
        "blacklist_count": len(data.get("blacklist", [])),
        "blacklists":      _extract_blacklists(data),
        "creation_time":   data.get("creation_time", "")[:10] if data.get("creation_time") else None,
        "modification_time": data.get("modification_time", "")[:10] if data.get("modification_time") else None,
    }


def handle_mv_hash(args):
    h    = args["hash"]
    data = mv_get(f"/sample/{h}")
    av   = data.get("av_ratio")
    return {
        "hash":            h,
        "md5":             data.get("md5"),
        "sha1":            data.get("sha1"),
        "sha256":          data.get("sha256"),
        "classification":  data.get("classification"),
        "score":           data.get("score"),
        "file_type":       data.get("filetype"),
        "file_size":       data.get("size"),
        "av_ratio":        av,
        "tags":            data.get("tag", []),
        "blacklist_count": len(data.get("blacklist", [])),
        "blacklists":      _extract_blacklists(data),
        "process_list":    data.get("process_list", [])[:10],
        "creation_time":   data.get("creation_time", "")[:10] if data.get("creation_time") else None,
    }


def handle_mv_search(args):
    query = args["query"]
    limit = int(args.get("limit", 10))
    type_ = args.get("type")
    params = {"query": query, "size": limit}
    if type_:
        params["type"] = type_
    data    = mv_get("/search", params=params)
    results = data.get("hits", {}).get("hits", [])
    return {
        "query":   query,
        "total":   data.get("hits", {}).get("total", {}).get("value", len(results)),
        "results": [
            {
                "type":           r.get("_type") or r.get("_source", {}).get("type"),
                "id":             r.get("_id"),
                "classification": r.get("_source", {}).get("classification"),
                "score":          r.get("_source", {}).get("score"),
                "tags":           r.get("_source", {}).get("tag", []),
            }
            for r in results
        ],
    }


def handle_mv_feed(args):
    feed_id = args["feed_id"]
    limit   = int(args.get("limit", 20))
    data    = mv_get(f"/collection/{feed_id}/download", params={"size": limit})
    # Feed response varies; can be a list or dict with results
    if isinstance(data, list):
        items = data[:limit]
    else:
        items = data.get("results", data.get("hits", {}).get("hits", []))[:limit]
    return {
        "feed_id": feed_id,
        "count":   len(items),
        "items":   items,
    }


HANDLERS = {
    "mv_ip":     handle_mv_ip,
    "mv_domain": handle_mv_domain,
    "mv_url":    handle_mv_url,
    "mv_hash":   handle_mv_hash,
    "mv_search": handle_mv_search,
    "mv_feed":   handle_mv_feed,
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
                "serverInfo": {"name": "maltiverse-mcp", "version": "1.0.0"},
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
