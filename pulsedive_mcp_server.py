#!/usr/bin/env python3
"""
MCP server for Pulsedive threat intelligence.
API key from https://pulsedive.com — free account.
Save to ~/.pulsedive_key
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
    path = os.path.expanduser("~/.pulsedive_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return ""  # Pulsedive allows limited use without key

def pd_get(endpoint, params=None):
    key = load_key()
    base_params = {}
    if key:
        base_params["key"] = key
    if params:
        base_params.update(params)
    url = f"https://pulsedive.com/api/{endpoint}"
    if base_params:
        url += "?" + urllib.parse.urlencode(base_params)
    req = urllib.request.Request(url, headers={
        "User-Agent": "mcp-pulsedive/1.0",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "pd_indicator",
        "description": "Look up a threat indicator in Pulsedive by value. Supports IPs, domains, URLs and file hashes. Returns risk score, threats, feeds, and attributes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "IP, domain, URL, or hash to look up"},
                "with_threats": {"type": "boolean", "description": "Include associated threats (default true)"},
                "with_feeds":   {"type": "boolean", "description": "Include feed sources (default true)"},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "pd_threat",
        "description": "Get details about a named threat in Pulsedive (e.g. 'Emotet', 'Cobalt Strike', 'APT28'). Returns description, risk, indicators count, and linked threats.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "threat": {"type": "string", "description": "Threat name (e.g. 'Emotet', 'Cobalt Strike')"},
            },
            "required": ["threat"],
        },
    },
    {
        "name": "pd_feed",
        "description": "Get details about a threat feed in Pulsedive by name or ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "feed": {"type": "string", "description": "Feed name or ID"},
            },
            "required": ["feed"],
        },
    },
    {
        "name": "pd_search",
        "description": "Search Pulsedive for indicators, threats, or feeds matching a query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":  {"type": "string",  "description": "Search term"},
                "type":   {"type": "string",  "description": "Result type: indicator, threat, feed (default: all)"},
                "risk":   {"type": "string",  "description": "Filter by risk: none, low, medium, high, critical, unknown"},
                "limit":  {"type": "integer", "description": "Number of results (default 10)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "pd_analyze",
        "description": "Submit a new indicator to Pulsedive for analysis and enrichment. Returns enriched data including WHOIS, DNS, and threat context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "IP, domain, URL, or hash to analyze"},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "pd_feed_indicators",
        "description": "Get indicators belonging to a specific Pulsedive feed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "feed_id": {"type": "integer", "description": "Feed ID (get from pd_feed)"},
                "limit":   {"type": "integer", "description": "Number of indicators (default 20)"},
            },
            "required": ["feed_id"],
        },
    },
    {
        "name": "pd_threat_indicators",
        "description": "Get indicators linked to a specific threat in Pulsedive.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "threat_id": {"type": "integer", "description": "Threat ID (get from pd_threat)"},
                "limit":     {"type": "integer", "description": "Number of indicators (default 20)"},
            },
            "required": ["threat_id"],
        },
    },
]


def _risk_label(risk):
    return {
        "none":     "none",
        "low":      "low",
        "medium":   "medium",
        "high":     "high",
        "critical": "critical",
    }.get(str(risk).lower(), risk)


def handle_pd_indicator(args):
    ioc     = args["indicator"]
    threats = args.get("with_threats", True)
    feeds   = args.get("with_feeds", True)
    params  = {"indicator": ioc, "pretty": 1}
    if threats:
        params["with"] = "threats,attributes,feeds"
    data = pd_get("info.php", params)
    if data.get("error"):
        return {"error": data["error"], "indicator": ioc}

    result = {
        "indicator":    data.get("indicator"),
        "type":         data.get("type"),
        "risk":         data.get("risk"),
        "risk_recommended": data.get("risk_recommended"),
        "iid":          data.get("iid"),
        "stamp_added":  data.get("stamp_added", "")[:10] if data.get("stamp_added") else None,
        "stamp_seen":   data.get("stamp_seen", "")[:10] if data.get("stamp_seen") else None,
        "stamp_updated":data.get("stamp_updated", "")[:10] if data.get("stamp_updated") else None,
        "retired":      data.get("retired"),
        "summary":      data.get("summary"),
    }

    # Properties/attributes
    props = data.get("properties", {})
    if props:
        result["properties"] = {k: v for k, v in props.items() if v}

    # Threats
    t_list = data.get("threats", [])
    if t_list:
        result["threats"] = [
            {
                "name": t.get("name"),
                "category": t.get("category"),
                "risk": t.get("risk"),
                "tid": t.get("tid"),
            }
            for t in t_list[:10]
        ]

    # Feeds
    f_list = data.get("feeds", [])
    if f_list:
        result["feeds"] = [
            {
                "name": f.get("name"),
                "category": f.get("category"),
                "organization": f.get("organization"),
                "fid": f.get("fid"),
            }
            for f in f_list[:10]
        ]

    return result


def handle_pd_threat(args):
    threat = args["threat"]
    data   = pd_get("info.php", {"threat": threat, "pretty": 1, "with": "threats,feeds"})
    if data.get("error"):
        return {"error": data["error"], "threat": threat}
    return {
        "name":         data.get("name"),
        "tid":          data.get("tid"),
        "category":     data.get("category"),
        "risk":         data.get("risk"),
        "description":  (data.get("description") or "")[:500],
        "wiki":         data.get("wiki"),
        "stamp_added":  data.get("stamp_added", "")[:10] if data.get("stamp_added") else None,
        "stamp_updated":data.get("stamp_updated", "")[:10] if data.get("stamp_updated") else None,
        "indicator_count": data.get("indicator_count"),
        "linked_threats": [
            {"name": t.get("name"), "category": t.get("category"), "risk": t.get("risk")}
            for t in data.get("threats", [])[:5]
        ],
        "feeds": [
            {"name": f.get("name"), "organization": f.get("organization")}
            for f in data.get("feeds", [])[:5]
        ],
        "attributes": data.get("attributes", {}),
    }


def handle_pd_feed(args):
    feed = args["feed"]
    # Try by name first, then by ID
    try:
        fid = int(feed)
        data = pd_get("info.php", {"feed": fid, "pretty": 1})
    except ValueError:
        data = pd_get("info.php", {"feed": feed, "pretty": 1})
    if data.get("error"):
        return {"error": data["error"], "feed": feed}
    return {
        "name":         data.get("name"),
        "fid":          data.get("fid"),
        "category":     data.get("category"),
        "organization": data.get("organization"),
        "website":      data.get("website"),
        "risk":         data.get("risk"),
        "description":  (data.get("description") or "")[:500],
        "stamp_added":  data.get("stamp_added", "")[:10] if data.get("stamp_added") else None,
        "stamp_updated":data.get("stamp_updated", "")[:10] if data.get("stamp_updated") else None,
        "indicator_count": data.get("indicator_count"),
    }


def handle_pd_search(args):
    query = args["query"]
    limit = int(args.get("limit", 10))
    type_ = args.get("type", "")
    risk  = args.get("risk", "")
    params = {"q": query, "limit": limit, "pretty": 1}
    if type_:
        params["type"] = type_
    if risk:
        params["risk"] = risk
    data    = pd_get("search.php", params)
    results = data.get("results", [])
    return {
        "query":   query,
        "total":   data.get("total", len(results)),
        "results": [
            {
                "type":      r.get("type"),
                "indicator": r.get("indicator") or r.get("name"),
                "risk":      r.get("risk"),
                "id":        r.get("iid") or r.get("tid") or r.get("fid"),
                "stamp_seen": (r.get("stamp_seen") or "")[:10] or None,
            }
            for r in results[:limit]
        ],
    }


def handle_pd_analyze(args):
    ioc  = args["indicator"]
    # POST to analyze endpoint
    key  = load_key()
    body = {"value": ioc, "probe": 1}
    if key:
        body["key"] = key
    raw  = json.dumps(body).encode()
    req  = urllib.request.Request(
        "https://pulsedive.com/api/analyze.php",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "mcp-pulsedive/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode())
    if data.get("error"):
        return {"error": data["error"]}
    # Poll for result
    qid = data.get("qid")
    if qid:
        import time
        for _ in range(10):
            time.sleep(3)
            status = pd_get("analyze.php", {"qid": qid})
            if status.get("status") == "done":
                return status.get("data", status)
        return {"qid": qid, "status": "pending", "message": "Analysis submitted but not yet complete. Retry with qid."}
    return data


def handle_pd_feed_indicators(args):
    fid   = int(args["feed_id"])
    limit = int(args.get("limit", 20))
    data  = pd_get("info.php", {"feed": fid, "with": "indicators", "limit": limit, "pretty": 1})
    if data.get("error"):
        return {"error": data["error"], "feed_id": fid}
    indicators = data.get("indicators", [])
    return {
        "feed_id":   fid,
        "feed_name": data.get("name"),
        "count":     len(indicators),
        "indicators": [
            {
                "indicator": i.get("indicator"),
                "type":      i.get("type"),
                "risk":      i.get("risk"),
                "stamp_seen": (i.get("stamp_seen") or "")[:10] or None,
            }
            for i in indicators[:limit]
        ],
    }


def handle_pd_threat_indicators(args):
    tid   = int(args["threat_id"])
    limit = int(args.get("limit", 20))
    data  = pd_get("info.php", {"threat": tid, "with": "indicators", "limit": limit, "pretty": 1})
    if data.get("error"):
        return {"error": data["error"], "threat_id": tid}
    indicators = data.get("indicators", [])
    return {
        "threat_id":   tid,
        "threat_name": data.get("name"),
        "count":       len(indicators),
        "indicators": [
            {
                "indicator": i.get("indicator"),
                "type":      i.get("type"),
                "risk":      i.get("risk"),
                "stamp_seen": (i.get("stamp_seen") or "")[:10] or None,
            }
            for i in indicators[:limit]
        ],
    }


HANDLERS = {
    "pd_indicator":        handle_pd_indicator,
    "pd_threat":           handle_pd_threat,
    "pd_feed":             handle_pd_feed,
    "pd_search":           handle_pd_search,
    "pd_analyze":          handle_pd_analyze,
    "pd_feed_indicators":  handle_pd_feed_indicators,
    "pd_threat_indicators":handle_pd_threat_indicators,
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
                "serverInfo": {"name": "pulsedive-mcp", "version": "1.0.0"},
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
