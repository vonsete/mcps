#!/usr/bin/env python3
"""
MCP server for Hybrid Analysis (Falcon Sandbox) malware analysis.
Free API key from https://www.hybrid-analysis.com/
Save to ~/.hybrid_analysis_key
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
    path = os.path.expanduser("~/.hybrid_analysis_key")
    if not os.path.exists(path):
        raise RuntimeError("Hybrid Analysis API key not found. Save it to ~/.hybrid_analysis_key")
    with open(path) as f:
        return f.read().strip()

def ha_get(path, params=None):
    key = load_key()
    url = f"https://www.hybrid-analysis.com/api/v2{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "api-key":    key,
        "User-Agent": "Falcon Sandbox",
        "Accept":     "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def ha_post(path, payload, form=False):
    key  = load_key()
    url  = f"https://www.hybrid-analysis.com/api/v2{path}"
    if form:
        data = urllib.parse.urlencode(payload).encode()
        ctype = "application/x-www-form-urlencoded"
    else:
        data  = json.dumps(payload).encode()
        ctype = "application/json"
    req = urllib.request.Request(url, data=data, headers={
        "api-key":      key,
        "User-Agent":   "Falcon Sandbox",
        "Accept":       "application/json",
        "Content-Type": ctype,
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "ha_search",
        "description": "Search Hybrid Analysis for reports by hash (MD5/SHA1/SHA256), filename, or similar samples. Returns matching reports with threat scores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash":     {"type": "string", "description": "MD5, SHA1 or SHA256 hash"},
                "filename": {"type": "string", "description": "Filename to search for"},
                "filetype": {"type": "string", "description": "File type: exe, pdf, doc, etc."},
                "country":  {"type": "string", "description": "2-letter country code of submission origin"},
                "limit":    {"type": "integer","description": "Number of results (default 10, max 200)"},
            },
        },
    },
    {
        "name": "ha_lookup_hash",
        "description": "Get all sandbox reports for a file hash (MD5/SHA1/SHA256). Returns threat score, verdict, malware families, and summary per environment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "MD5, SHA1 or SHA256 hash"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "ha_report_summary",
        "description": "Get the full summary report for a specific analysis (by job ID or SHA256 + environment). Includes process tree, network activity, dropped files, registry changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id":          {"type": "string",  "description": "Job ID from ha_submit_url or ha_search"},
                "sha256":      {"type": "string",  "description": "SHA256 hash (alternative to id, requires environment_id)"},
                "environment_id": {"type": "integer", "description": "Environment ID: 300=Linux, 110=Win7 32bit, 120=Win7 64bit, 140=Win10 64bit"},
            },
        },
    },
    {
        "name": "ha_iocs",
        "description": "Extract IOCs (IPs, domains, URLs, file hashes, registry keys, mutexes) from a report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id":          {"type": "string",  "description": "Job ID"},
                "sha256":      {"type": "string",  "description": "SHA256 hash"},
                "environment_id": {"type": "integer", "description": "Environment ID (default 120 = Win7 64bit)"},
            },
        },
    },
    {
        "name": "ha_submit_url",
        "description": "Submit a URL or file URL for sandbox analysis. Returns job ID. Use ha_report_summary to get results once complete (usually 2-5 minutes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":            {"type": "string",  "description": "URL to analyse (web page or direct file link)"},
                "environment_id": {"type": "integer", "description": "Sandbox environment: 300=Linux, 110=Win7 32bit, 120=Win7 64bit (default), 140=Win10 64bit"},
                "wait":           {"type": "boolean", "description": "Wait for analysis to complete and return report (default false, max wait 5min)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "ha_environments",
        "description": "List available sandbox environments with their IDs, OS, architecture and description.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "ha_verdict",
        "description": "Quick verdict check for a hash: returns threat score (0-100), verdict (no-verdict/whitelisted/no-specific-threat/suspicious/malicious), and malware family if known.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "MD5, SHA1 or SHA256 hash"},
            },
            "required": ["hash"],
        },
    },
]


# ── env IDs ─────────────────────────────────────────────────────────────────
ENV_NAMES = {
    300: "Linux (Ubuntu 20.04)",
    110: "Windows 7 32-bit",
    120: "Windows 7 64-bit",
    140: "Windows 10 64-bit",
}

def _fmt_report(r):
    return {
        "job_id":          r.get("job_id"),
        "sha256":          r.get("sha256"),
        "md5":             r.get("md5"),
        "sha1":            r.get("sha1"),
        "environment_id":  r.get("environment_id"),
        "environment_desc":r.get("environment_description") or ENV_NAMES.get(r.get("environment_id"), ""),
        "verdict":         r.get("verdict"),
        "threat_score":    r.get("threat_score"),
        "threat_level":    r.get("threat_level"),
        "malware_family":  r.get("vx_family"),
        "type":            r.get("type"),
        "type_short":      r.get("type_short"),
        "submit_name":     r.get("submit_name"),
        "analysis_start":  (r.get("analysis_start_time") or "")[:10] or None,
        "size":            r.get("size"),
        "tags":            r.get("tags", []),
        "classification":  r.get("classification_tags", []),
    }


def handle_ha_search(args):
    payload = {}
    if "hash"     in args: payload["hash"]     = args["hash"]
    if "filename" in args: payload["filename"]  = args["filename"]
    if "filetype" in args: payload["filetype"]  = args["filetype"]
    if "country"  in args: payload["country"]   = args["country"]
    limit = min(int(args.get("limit", 10)), 200)
    payload["_limit"] = limit
    data = ha_post("/search/hash", payload, form=True) if "hash" in payload and len(payload) == 2 else ha_post("/search/terms", payload, form=True)
    # search/hash returns a list, search/terms returns {"result": [...], "count": N}
    if isinstance(data, list):
        results = data[:limit]
    else:
        results = data.get("result", data.get("results", []))[:limit]
    return {"count": len(results), "results": [_fmt_report(r) for r in results]}


def handle_ha_lookup_hash(args):
    h    = args["hash"]
    data = ha_get(f"/report/{urllib.parse.quote(h)}/summary")
    # Returns a list of reports across environments
    if isinstance(data, list):
        return {"hash": h, "count": len(data), "reports": [_fmt_report(r) for r in data]}
    return {"hash": h, "report": _fmt_report(data)}


def handle_ha_report_summary(args):
    if "id" in args:
        data = ha_get(f"/report/{args['id']}/summary")
    elif "sha256" in args:
        env  = args.get("environment_id", 120)
        data = ha_get(f"/report/{args['sha256']}:{env}/summary")
    else:
        return {"error": "Provide id or sha256"}

    if isinstance(data, list):
        data = data[0] if data else {}

    result = _fmt_report(data)
    # Enrich with detail fields
    result.update({
        "mitre_attcks":   [
            {"tactic": m.get("tactic"), "technique": m.get("technique"), "id": m.get("attck_id")}
            for m in (data.get("mitre_attcks") or [])[:10]
        ],
        "processes":      len(data.get("processes") or []),
        "network_domains":[h.get("domain") for h in (data.get("domains") or [])[:10]],
        "network_hosts":  [h.get("ip") for h in (data.get("hosts") or [])[:10]],
        "network_urls":   [(u.get("url") or u.get("request") or "") for u in (data.get("compromised_hosts") or [])[:5]],
        "dropped_files":  len(data.get("extracted_files") or []),
        "signatures":     [
            {"name": s.get("name"), "severity": s.get("threat_level_human")}
            for s in (data.get("signatures") or [])[:15]
        ],
    })
    return result


def handle_ha_iocs(args):
    if "id" in args:
        rid = args["id"]
    elif "sha256" in args:
        env = args.get("environment_id", 120)
        rid = f"{args['sha256']}:{env}"
    else:
        return {"error": "Provide id or sha256"}

    data = ha_get(f"/report/{rid}/summary")
    if isinstance(data, list):
        data = data[0] if data else {}

    return {
        "job_id":        data.get("job_id"),
        "sha256":        data.get("sha256"),
        "verdict":       data.get("verdict"),
        "threat_score":  data.get("threat_score"),
        "domains":       [d.get("domain") for d in (data.get("domains") or [])],
        "hosts":         [h.get("ip") for h in (data.get("hosts") or [])],
        "urls":          [(u.get("url") or "") for u in (data.get("compromised_hosts") or [])],
        "mutexes":       [m.get("name") for m in (data.get("mutants") or [])[:20]],
        "registry":      [r.get("key") for r in (data.get("registry") or [])[:20]],
        "dropped_hashes":[f.get("sha256") for f in (data.get("extracted_files") or []) if f.get("sha256")][:20],
        "processes":     [
            {"name": p.get("name"), "pid": p.get("pid"), "cmd": (p.get("commandline") or "")[:120]}
            for p in (data.get("processes") or [])[:20]
        ],
    }


def handle_ha_submit_url(args):
    url    = args["url"]
    env_id = int(args.get("environment_id", 120))
    wait   = bool(args.get("wait", False))

    payload = {"url": url, "environment_id": env_id}
    data    = ha_post("/submit/url", payload, form=True)
    job_id  = data.get("job_id") or data.get("id")
    sha256  = data.get("sha256")

    if not wait or not job_id:
        return {
            "submitted": True,
            "job_id":    job_id,
            "sha256":    sha256,
            "environment_id": env_id,
            "message":   "Use ha_report_summary with this job_id once analysis completes (2-5 min).",
        }

    # Poll for completion
    for _ in range(30):
        time.sleep(10)
        try:
            report = ha_get(f"/report/{job_id}/summary")
            if isinstance(report, list):
                report = report[0] if report else {}
            if report.get("state") in ("SUCCESS", "ERROR") or report.get("verdict"):
                return _fmt_report(report)
        except Exception:
            pass

    return {"job_id": job_id, "status": "pending", "message": "Analysis not complete after 5 min. Check later with ha_report_summary."}


def handle_ha_environments(args):
    data = ha_get("/system/environments")
    return {
        "environments": [
            {
                "id":          e.get("ID"),
                "description": e.get("description"),
                "architecture":e.get("architecture"),
                "os":          e.get("os"),
                "os_version":  e.get("os_version"),
            }
            for e in data
        ]
    }


def handle_ha_verdict(args):
    h    = args["hash"]
    data = ha_get(f"/report/{urllib.parse.quote(h)}/summary")
    if isinstance(data, list):
        # Pick best (highest threat score) report
        data = sorted(data, key=lambda r: r.get("threat_score") or 0, reverse=True)
        data = data[0] if data else {}
    return {
        "hash":          h,
        "sha256":        data.get("sha256"),
        "verdict":       data.get("verdict"),
        "threat_score":  data.get("threat_score"),
        "threat_level":  data.get("threat_level"),
        "malware_family":data.get("vx_family"),
        "environment":   data.get("environment_description"),
        "type":          data.get("type"),
        "tags":          data.get("tags", []),
    }


HANDLERS = {
    "ha_search":         handle_ha_search,
    "ha_lookup_hash":    handle_ha_lookup_hash,
    "ha_report_summary": handle_ha_report_summary,
    "ha_iocs":           handle_ha_iocs,
    "ha_submit_url":     handle_ha_submit_url,
    "ha_environments":   handle_ha_environments,
    "ha_verdict":        handle_ha_verdict,
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
                "serverInfo": {"name": "hybridanalysis-mcp", "version": "1.0.0"},
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
