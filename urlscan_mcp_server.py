#!/usr/bin/env python3
"""
MCP server for URLScan.io.
Search is free (no key). Submissions require API key from ~/.urlscan_key
"""

import sys
import json
import os
import urllib.request
import urllib.parse
import time


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
    path = os.path.expanduser("~/.urlscan_key")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read().strip() or None

def api_request(method, path, data=None, key=None):
    url     = f"https://urlscan.io/api/v1{path}"
    headers = {"Content-Type": "application/json", "User-Agent": "mcp-urlscan/1.0"}
    if key:
        headers["API-Key"] = key
    body = json.dumps(data).encode() if data else None
    req  = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "urlscan_search",
        "description": "Search URLScan.io for past scans of a URL, domain or IP. No API key needed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g. 'domain:evil.com', 'ip:1.2.3.4', 'page.url:phishing')"},
                "size":  {"type": "integer", "description": "Number of results (default 10, max 100)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "urlscan_submit",
        "description": "Submit a URL for scanning and wait for the result. Requires API key in ~/.urlscan_key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":        {"type": "string", "description": "URL to scan"},
                "visibility": {"type": "string", "description": "Scan visibility: public, unlisted, private (default public)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "urlscan_result",
        "description": "Get the full result of a previous URLScan scan by UUID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uuid": {"type": "string", "description": "Scan UUID from urlscan_submit or urlscan_search"},
            },
            "required": ["uuid"],
        },
    },
    {
        "name": "urlscan_domain",
        "description": "Get a summary of all past scans for a domain: IPs contacted, verdicts, screenshots.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up (e.g. 'evil.com')"},
                "size":   {"type": "integer", "description": "Number of results (default 10)"},
            },
            "required": ["domain"],
        },
    },
]


def parse_result(r):
    task    = r.get("task", {})
    page    = r.get("page", {})
    verdict = r.get("verdicts", {}).get("overall", {})
    stats   = r.get("stats", {})
    return {
        "uuid":        task.get("uuid"),
        "url":         task.get("url"),
        "time":        task.get("time"),
        "screenshot":  f"https://urlscan.io/screenshots/{task.get('uuid')}.png" if task.get("uuid") else None,
        "report":      f"https://urlscan.io/result/{task.get('uuid')}/" if task.get("uuid") else None,
        "domain":      page.get("domain"),
        "ip":          page.get("ip"),
        "country":     page.get("country"),
        "server":      page.get("server"),
        "title":       page.get("title"),
        "status":      page.get("status"),
        "malicious":   verdict.get("malicious"),
        "score":       verdict.get("score"),
        "categories":  verdict.get("categories", []),
        "brands":      verdict.get("brands", []),
        "requests":    stats.get("requests"),
        "domains":     stats.get("uniqDomains"),
        "ips":         stats.get("uniqIPs"),
    }


def handle_urlscan_search(args):
    query = args["query"]
    size  = min(int(args.get("size", 10)), 100)
    url   = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(query)}&size={size}"
    req   = urllib.request.Request(url, headers={"User-Agent": "mcp-urlscan/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.loads(r.read().decode())
    results = data.get("results", [])
    return {
        "total":   data.get("total", len(results)),
        "results": [parse_result(r) for r in results],
    }


def handle_urlscan_submit(args):
    key = load_key()
    if not key:
        return {"error": "API key required. Save it to ~/.urlscan_key"}
    body = {
        "url":        args["url"],
        "visibility": args.get("visibility", "public"),
    }
    sub  = api_request("POST", "/scan/", data=body, key=key)
    uuid = sub.get("uuid")
    if not uuid:
        return {"error": "Submission failed", "response": sub}

    # Poll for result (max 60s)
    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    for attempt in range(12):
        time.sleep(5)
        try:
            req = urllib.request.Request(result_url, headers={"User-Agent": "mcp-urlscan/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
                parsed = parse_result(data)
                parsed["status"] = "complete"
                return parsed
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
    return {"uuid": uuid, "status": "pending", "report": f"https://urlscan.io/result/{uuid}/"}


def handle_urlscan_result(args):
    uuid = args["uuid"]
    url  = f"https://urlscan.io/api/v1/result/{uuid}/"
    req  = urllib.request.Request(url, headers={"User-Agent": "mcp-urlscan/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.loads(r.read().decode())
    return parse_result(data)


def handle_urlscan_domain(args):
    domain = args["domain"]
    size   = int(args.get("size", 10))
    return handle_urlscan_search({"query": f"domain:{domain}", "size": size})


HANDLERS = {
    "urlscan_search": handle_urlscan_search,
    "urlscan_submit": handle_urlscan_submit,
    "urlscan_result": handle_urlscan_result,
    "urlscan_domain": handle_urlscan_domain,
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
                "serverInfo": {"name": "urlscan-mcp", "version": "1.0.0"},
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
