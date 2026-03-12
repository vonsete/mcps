#!/usr/bin/env python3
"""
MCP server for CVE / NVD vulnerability lookups.
Uses NIST NVD API v2 — no API key required (free, 5 req/30s without key).
Optionally reads API key from ~/.nvd_key for higher rate limits.
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

def nvd_get(path, params):
    base = "https://services.nvd.nist.gov/rest/json"
    url  = f"{base}{path}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "mcp-cve/1.0"}
    key_path = os.path.expanduser("~/.nvd_key")
    if os.path.exists(key_path):
        with open(key_path) as f:
            headers["apiKey"] = f.read().strip()
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "cve_lookup",
        "description": "Get full details of a specific CVE by ID (e.g. CVE-2021-44228 Log4Shell).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE identifier (e.g. 'CVE-2021-44228')"},
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "cve_search",
        "description": "Search CVEs by keyword, product, vendor or CVSS score range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword":       {"type": "string",  "description": "Keyword to search (e.g. 'apache log4j', 'openssl')"},
                "cvss_min":      {"type": "number",  "description": "Minimum CVSS v3 score (0-10)"},
                "cvss_max":      {"type": "number",  "description": "Maximum CVSS v3 score (0-10)"},
                "results_per_page": {"type": "integer", "description": "Results to return (default 10, max 2000)"},
            },
        },
    },
    {
        "name": "cve_by_product",
        "description": "Find CVEs affecting a specific CPE product (e.g. 'cpe:2.3:a:apache:log4j:*').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cpe_name":         {"type": "string",  "description": "CPE 2.3 string (e.g. 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*')"},
                "results_per_page": {"type": "integer", "description": "Results to return (default 10)"},
            },
            "required": ["cpe_name"],
        },
    },
    {
        "name": "cve_recent",
        "description": "Get recently published or modified CVEs, optionally filtered by minimum CVSS score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days":     {"type": "integer", "description": "How many days back to look (default 7, max 120)"},
                "cvss_min": {"type": "number",  "description": "Minimum CVSS v3 score filter (e.g. 7.0 for High+)"},
                "results_per_page": {"type": "integer", "description": "Results (default 20)"},
            },
        },
    },
]


def parse_cve(item):
    cve   = item.get("cve", {})
    cve_id = cve.get("id")
    desc  = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None)
    # CVSS v3
    metrics = cve.get("metrics", {})
    cvss3   = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m       = metrics[key][0]["cvssData"]
            cvss3   = m.get("baseScore")
            severity = m.get("baseSeverity")
            break
    # CVSS v2 fallback
    cvss2 = None
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss2 = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")

    refs = [r["url"] for r in cve.get("references", [])[:5]]
    published = cve.get("published", "")[:10]
    modified  = cve.get("lastModified", "")[:10]
    weaknesses = [
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("lang") == "en"
    ]

    return {
        "id":          cve_id,
        "published":   published,
        "modified":    modified,
        "cvss_v3":     cvss3,
        "cvss_v2":     cvss2,
        "severity":    severity,
        "description": desc,
        "weaknesses":  weaknesses,
        "references":  refs,
    }


def handle_cve_lookup(args):
    cve_id = args["cve_id"].upper()
    data   = nvd_get("/cves/2.0", {"cveId": cve_id})
    vulns  = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"CVE {cve_id} not found"}
    return parse_cve(vulns[0])


def handle_cve_search(args):
    params = {"resultsPerPage": args.get("results_per_page", 10)}
    if args.get("keyword"):
        params["keywordSearch"] = args["keyword"]
    if args.get("cvss_min") is not None:
        params["cvssV3ScoreGte"] = args["cvss_min"]
    if args.get("cvss_max") is not None:
        params["cvssV3ScoreLte"] = args["cvss_max"]
    data  = nvd_get("/cves/2.0", params)
    vulns = data.get("vulnerabilities", [])
    return {
        "total":   data.get("totalResults", 0),
        "returned": len(vulns),
        "results": [parse_cve(v) for v in vulns],
    }


def handle_cve_by_product(args):
    params = {
        "cpeName":        args["cpe_name"],
        "resultsPerPage": args.get("results_per_page", 10),
    }
    data  = nvd_get("/cves/2.0", params)
    vulns = data.get("vulnerabilities", [])
    return {
        "total":   data.get("totalResults", 0),
        "returned": len(vulns),
        "results": [parse_cve(v) for v in vulns],
    }


def handle_cve_recent(args):
    import datetime
    days = min(int(args.get("days", 7)), 120)
    now  = datetime.datetime.utcnow()
    start = now - datetime.timedelta(days=days)
    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate":     now.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": args.get("results_per_page", 20),
    }
    if args.get("cvss_min") is not None:
        params["cvssV3ScoreGte"] = args["cvss_min"]
    data  = nvd_get("/cves/2.0", params)
    vulns = data.get("vulnerabilities", [])
    return {
        "period_days": days,
        "total":       data.get("totalResults", 0),
        "returned":    len(vulns),
        "results":     [parse_cve(v) for v in vulns],
    }


HANDLERS = {
    "cve_lookup":      handle_cve_lookup,
    "cve_search":      handle_cve_search,
    "cve_by_product":  handle_cve_by_product,
    "cve_recent":      handle_cve_recent,
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
                "serverInfo": {"name": "cve-mcp", "version": "1.0.0"},
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
