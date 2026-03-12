#!/usr/bin/env python3
"""
MCP server for Abuse.ch threat intelligence.
Covers three APIs in one server:
  - MalwareBazaar  : malware sample repository
  - URLhaus        : malicious URL tracking
  - ThreatFox      : IOC sharing platform

All APIs are free and require no key by default.
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
    """Load optional Abuse.ch API key from ~/.abusech_key"""
    path = os.path.expanduser("~/.abusech_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return ""


# ── HTTP helpers ────────────────────────────────────────────────────────────

def post_json(url, payload):
    key     = load_key()
    data    = urllib.parse.urlencode(payload).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent":   "mcp-abusech/1.0",
    }
    if key:
        headers["Auth-Key"] = key
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def post_body(url, payload):
    key     = load_key()
    data    = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent":   "mcp-abusech/1.0",
    }
    if key:
        headers["Auth-Key"] = key
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


# ── Tool definitions ────────────────────────────────────────────────────────

TOOLS = [
    # ── MalwareBazaar ──
    {
        "name": "bazaar_lookup_hash",
        "description": "Look up a malware sample in MalwareBazaar by MD5, SHA1, SHA256 or SHA3-384 hash. Returns file type, size, tags, signatures, AV detections and C2 info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "File hash (MD5/SHA1/SHA256/SHA3-384)"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "bazaar_search_tag",
        "description": "Search MalwareBazaar samples by tag (e.g. 'Emotet', 'AgentTesla', 'docx').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag":   {"type": "string",  "description": "Tag to search for"},
                "limit": {"type": "integer", "description": "Number of results (default 10, max 1000)"},
            },
            "required": ["tag"],
        },
    },
    {
        "name": "bazaar_search_signature",
        "description": "Search MalwareBazaar by signature/malware family name (e.g. 'Cobalt Strike', 'Qbot').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "signature": {"type": "string",  "description": "Malware signature/family name"},
                "limit":     {"type": "integer", "description": "Number of results (default 10)"},
            },
            "required": ["signature"],
        },
    },
    {
        "name": "bazaar_recent",
        "description": "Get recently submitted malware samples in MalwareBazaar.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of results (default 10, max 1000)"},
            },
        },
    },
    # ── URLhaus ──
    {
        "name": "urlhaus_lookup_url",
        "description": "Look up a URL in URLhaus. Returns threat status, tags, payloads hosted and blacklist status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to look up"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "urlhaus_lookup_host",
        "description": "Look up a domain or IP in URLhaus. Returns all malicious URLs associated with the host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Domain or IP address"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "urlhaus_lookup_hash",
        "description": "Look up a payload hash (MD5/SHA256) in URLhaus. Returns URLs that hosted this payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "MD5 or SHA256 hash of payload"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "urlhaus_recent",
        "description": "Get recently added malicious URLs from URLhaus.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of results (default 10, max 1000)"},
            },
        },
    },
    # ── ThreatFox ──
    {
        "name": "threatfox_lookup_ioc",
        "description": "Search ThreatFox for an IOC (IP:port, domain, URL, or file hash). Returns malware family, confidence, tags and first/last seen.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IOC value: IP:port, domain, URL, or hash"},
            },
            "required": ["ioc"],
        },
    },
    {
        "name": "threatfox_search_malware",
        "description": "Search ThreatFox IOCs by malware family name (e.g. 'Emotet', 'CobaltStrike', 'Raccoon').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "malware": {"type": "string",  "description": "Malware family name"},
                "limit":   {"type": "integer", "description": "Number of results (default 10, max 1000)"},
            },
            "required": ["malware"],
        },
    },
    {
        "name": "threatfox_search_tag",
        "description": "Search ThreatFox IOCs by tag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag":   {"type": "string",  "description": "Tag to search"},
                "limit": {"type": "integer", "description": "Number of results (default 10)"},
            },
            "required": ["tag"],
        },
    },
    {
        "name": "threatfox_recent",
        "description": "Get recent IOCs from ThreatFox, optionally filtered by days back.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days":  {"type": "integer", "description": "Days to look back (default 3, max 90)"},
                "limit": {"type": "integer", "description": "Number of results (default 20)"},
            },
        },
    },
]


# ── MalwareBazaar handlers ──────────────────────────────────────────────────

BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

def _fmt_bazaar_sample(s):
    return {
        "sha256":      s.get("sha256_hash"),
        "sha1":        s.get("sha1_hash"),
        "md5":         s.get("md5_hash"),
        "file_type":   s.get("file_type"),
        "file_size":   s.get("file_size"),
        "mime_type":   s.get("mime_type"),
        "signature":   s.get("signature"),
        "tags":        s.get("tags", []),
        "first_seen":  (s.get("first_seen") or "")[:10] or None,
        "last_seen":   (s.get("last_seen") or "")[:10] or None,
        "reporter":    s.get("reporter"),
        "origin":      s.get("origin"),
        "vendor_intel": s.get("vendor_intel", {}),
        "intelligence": s.get("intelligence", {}),
    }

def handle_bazaar_lookup_hash(args):
    data = post_json(BAZAAR_URL, {"query": "get_info", "hash": args["hash"]})
    if data.get("query_status") != "hash_found":
        return {"status": data.get("query_status"), "hash": args["hash"]}
    samples = data.get("data", [])
    return {
        "found":   True,
        "count":   len(samples),
        "samples": [_fmt_bazaar_sample(s) for s in samples],
    }

def handle_bazaar_search_tag(args):
    limit = min(int(args.get("limit", 10)), 1000)
    data  = post_json(BAZAAR_URL, {"query": "get_taginfo", "tag": args["tag"], "limit": limit})
    if data.get("query_status") != "tag_found":
        return {"status": data.get("query_status"), "tag": args["tag"]}
    samples = data.get("data", [])
    return {"tag": args["tag"], "count": len(samples), "samples": [_fmt_bazaar_sample(s) for s in samples]}

def handle_bazaar_search_signature(args):
    limit = min(int(args.get("limit", 10)), 1000)
    data  = post_json(BAZAAR_URL, {"query": "get_siginfo", "signature": args["signature"], "limit": limit})
    if data.get("query_status") not in ("signature_found", "ok"):
        return {"status": data.get("query_status"), "signature": args["signature"]}
    samples = data.get("data", [])
    return {"signature": args["signature"], "count": len(samples), "samples": [_fmt_bazaar_sample(s) for s in samples]}

def handle_bazaar_recent(args):
    limit = min(int(args.get("limit", 10)), 1000)
    data  = post_json(BAZAAR_URL, {"query": "get_recent", "selector": "time", "limit": limit})
    samples = data.get("data", [])
    return {"count": len(samples), "samples": [_fmt_bazaar_sample(s) for s in samples]}


# ── URLhaus handlers ────────────────────────────────────────────────────────

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"

def _fmt_urlhaus_url(u):
    return {
        "url":          u.get("url"),
        "url_status":   u.get("url_status"),
        "threat":       u.get("threat"),
        "tags":         u.get("tags", []),
        "date_added":   (u.get("date_added") or "")[:10] or None,
        "blacklists":   u.get("blacklists", {}),
        "payloads":     [
            {
                "md5":       p.get("response_md5"),
                "sha256":    p.get("response_sha256"),
                "file_type": p.get("file_type"),
                "signature": p.get("signature"),
            }
            for p in (u.get("payloads") or [])[:5]
        ],
    }

def handle_urlhaus_lookup_url(args):
    data = post_json(URLHAUS_URL + "url/", {"url": args["url"]})
    if data.get("query_status") != "is_available":
        return {"status": data.get("query_status"), "url": args["url"]}
    return _fmt_urlhaus_url(data)

def handle_urlhaus_lookup_host(args):
    data = post_json(URLHAUS_URL + "host/", {"host": args["host"]})
    if data.get("query_status") != "is_listed":
        return {"status": data.get("query_status"), "host": args["host"]}
    urls = data.get("urls", [])
    return {
        "host":       args["host"],
        "url_count":  data.get("url_count"),
        "blacklists": data.get("blacklists", {}),
        "urls":       [_fmt_urlhaus_url(u) for u in urls[:20]],
    }

def handle_urlhaus_lookup_hash(args):
    h    = args["hash"]
    key  = "md5_hash" if len(h) == 32 else "sha256_hash"
    data = post_json(URLHAUS_URL + "payload/", {key: h})
    if data.get("query_status") != "ok":
        return {"status": data.get("query_status"), "hash": h}
    return {
        "md5":       data.get("md5_hash"),
        "sha256":    data.get("sha256_hash"),
        "file_type": data.get("file_type"),
        "signature": data.get("signature"),
        "file_size": data.get("file_size"),
        "urls":      [u.get("url") for u in (data.get("urls") or [])[:10]],
    }

def handle_urlhaus_recent(args):
    limit = min(int(args.get("limit", 10)), 1000)
    data  = post_json(URLHAUS_URL + "urls/recent/", {"limit": limit})
    urls  = data.get("urls", [])
    return {"count": len(urls), "urls": [_fmt_urlhaus_url(u) for u in urls]}


# ── ThreatFox handlers ──────────────────────────────────────────────────────

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

def _fmt_ioc(i):
    return {
        "ioc":          i.get("ioc"),
        "ioc_type":     i.get("ioc_type"),
        "threat_type":  i.get("threat_type"),
        "malware":      i.get("malware"),
        "malware_alias":i.get("malware_alias"),
        "confidence":   i.get("confidence_level"),
        "tags":         i.get("tags", []),
        "first_seen":   (i.get("first_seen") or "")[:10] or None,
        "last_seen":    (i.get("last_seen") or "")[:10] or None,
        "reporter":     i.get("reporter"),
        "reference":    i.get("reference"),
    }

def handle_threatfox_lookup_ioc(args):
    data = post_body(THREATFOX_URL, {"query": "search_ioc", "search_term": args["ioc"]})
    if data.get("query_status") != "ok" or not data.get("data"):
        return {"status": data.get("query_status"), "ioc": args["ioc"], "found": False}
    iocs = data["data"]
    return {"ioc": args["ioc"], "found": True, "count": len(iocs), "iocs": [_fmt_ioc(i) for i in iocs]}

def handle_threatfox_search_malware(args):
    limit = min(int(args.get("limit", 10)), 1000)
    data  = post_body(THREATFOX_URL, {"query": "search_malware", "search_term": args["malware"]})
    if data.get("query_status") != "ok" or not data.get("data"):
        return {"status": data.get("query_status"), "malware": args["malware"]}
    iocs = data["data"][:limit]
    return {"malware": args["malware"], "count": len(iocs), "iocs": [_fmt_ioc(i) for i in iocs]}

def handle_threatfox_search_tag(args):
    limit = min(int(args.get("limit", 10)), 1000)
    data  = post_body(THREATFOX_URL, {"query": "search_tag", "tag": args["tag"]})
    if data.get("query_status") != "ok" or not data.get("data"):
        return {"status": data.get("query_status"), "tag": args["tag"]}
    iocs = data["data"][:limit]
    return {"tag": args["tag"], "count": len(iocs), "iocs": [_fmt_ioc(i) for i in iocs]}

def handle_threatfox_recent(args):
    days  = min(int(args.get("days", 3)), 90)
    limit = int(args.get("limit", 20))
    data  = post_body(THREATFOX_URL, {"query": "get_iocs", "days": days})
    if data.get("query_status") != "ok" or not data.get("data"):
        return {"status": data.get("query_status")}
    iocs = data["data"][:limit]
    return {"days": days, "count": len(iocs), "iocs": [_fmt_ioc(i) for i in iocs]}


# ── Dispatch ────────────────────────────────────────────────────────────────

HANDLERS = {
    "bazaar_lookup_hash":       handle_bazaar_lookup_hash,
    "bazaar_search_tag":        handle_bazaar_search_tag,
    "bazaar_search_signature":  handle_bazaar_search_signature,
    "bazaar_recent":            handle_bazaar_recent,
    "urlhaus_lookup_url":       handle_urlhaus_lookup_url,
    "urlhaus_lookup_host":      handle_urlhaus_lookup_host,
    "urlhaus_lookup_hash":      handle_urlhaus_lookup_hash,
    "urlhaus_recent":           handle_urlhaus_recent,
    "threatfox_lookup_ioc":     handle_threatfox_lookup_ioc,
    "threatfox_search_malware": handle_threatfox_search_malware,
    "threatfox_search_tag":     handle_threatfox_search_tag,
    "threatfox_recent":         handle_threatfox_recent,
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
                "serverInfo": {"name": "abusech-mcp", "version": "1.0.0"},
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
