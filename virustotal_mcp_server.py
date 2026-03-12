#!/usr/bin/env python3
"""
MCP server for VirusTotal API v3.
API key loaded from VIRUSTOTAL_API_KEY env var or ~/.virustotal_key file.
"""

import sys
import json
import os
import time
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


def get_api_key():
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        key_file = os.path.expanduser("~/.virustotal_key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("VIRUSTOTAL_API_KEY="):
                        key = line.split("=", 1)[1].strip()
                    elif line and not line.startswith("#"):
                        key = line
    if not key:
        raise RuntimeError("VirusTotal API key not found. Set VIRUSTOTAL_API_KEY or create ~/.virustotal_key")
    return key


def vt_get(path, params=None):
    key = get_api_key()
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/{path}",
        headers={"x-apikey": key},
        params=params,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


def parse_stats(stats):
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout":    stats.get("timeout", 0),
    }


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "vt_scan_ip",
        "description": "Analyse an IP address with VirusTotal. Returns reputation, detections and WHOIS info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to analyse (e.g. '8.8.8.8')"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "vt_scan_domain",
        "description": "Analyse a domain with VirusTotal. Returns reputation, DNS records and detections.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to analyse (e.g. 'example.com')"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "vt_scan_url",
        "description": "Analyse a URL with VirusTotal. Returns detections and threat categories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyse"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "vt_scan_hash",
        "description": "Analyse a file hash (MD5, SHA1 or SHA256) with VirusTotal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "File hash to analyse (MD5, SHA1 or SHA256)"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "vt_upload_file",
        "description": "Upload a file to VirusTotal for analysis and return the full report once ready.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path to the file to upload"},
                "wait": {"type": "boolean", "description": "Wait for analysis to complete and return full report (default true). If false, returns the analysis ID immediately."},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "vt_get_comments",
        "description": "Get community comments for an IP, domain, URL or file hash.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["ip_addresses", "domains", "urls", "files"],
                    "description": "Type of resource",
                },
                "resource_id": {"type": "string", "description": "IP, domain, URL or hash"},
            },
            "required": ["resource_type", "resource_id"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_scan_ip(args):
    ip   = args.get("ip")
    data = vt_get(f"ip_addresses/{ip}")
    attr = data.get("data", {}).get("attributes", {})
    return {
        "ip":           ip,
        "stats":        parse_stats(attr.get("last_analysis_stats", {})),
        "reputation":   attr.get("reputation"),
        "country":      attr.get("country"),
        "asn":          attr.get("asn"),
        "as_owner":     attr.get("as_owner"),
        "network":      attr.get("network"),
        "tags":         attr.get("tags", []),
        "last_analysis": attr.get("last_analysis_date"),
        "malicious_engines": [
            {"engine": k, "result": v.get("result")}
            for k, v in attr.get("last_analysis_results", {}).items()
            if v.get("category") == "malicious"
        ],
    }


def handle_scan_domain(args):
    domain = args.get("domain")
    data   = vt_get(f"domains/{domain}")
    attr   = data.get("data", {}).get("attributes", {})
    return {
        "domain":       domain,
        "stats":        parse_stats(attr.get("last_analysis_stats", {})),
        "reputation":   attr.get("reputation"),
        "registrar":    attr.get("registrar"),
        "creation_date": attr.get("creation_date"),
        "tags":         attr.get("tags", []),
        "categories":   attr.get("categories", {}),
        "dns_records":  attr.get("last_dns_records", [])[:10],
        "malicious_engines": [
            {"engine": k, "result": v.get("result")}
            for k, v in attr.get("last_analysis_results", {}).items()
            if v.get("category") == "malicious"
        ],
    }


def handle_scan_url(args):
    import base64
    url     = args.get("url")
    url_id  = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data    = vt_get(f"urls/{url_id}")
    attr    = data.get("data", {}).get("attributes", {})
    return {
        "url":          url,
        "stats":        parse_stats(attr.get("last_analysis_stats", {})),
        "reputation":   attr.get("reputation"),
        "tags":         attr.get("tags", []),
        "categories":   attr.get("categories", {}),
        "last_analysis": attr.get("last_analysis_date"),
        "malicious_engines": [
            {"engine": k, "result": v.get("result")}
            for k, v in attr.get("last_analysis_results", {}).items()
            if v.get("category") == "malicious"
        ],
    }


def handle_scan_hash(args):
    hash_val = args.get("hash")
    data     = vt_get(f"files/{hash_val}")
    attr     = data.get("data", {}).get("attributes", {})
    return {
        "hash":         hash_val,
        "stats":        parse_stats(attr.get("last_analysis_stats", {})),
        "name":         attr.get("meaningful_name"),
        "type":         attr.get("type_description"),
        "size":         attr.get("size"),
        "tags":         attr.get("tags", []),
        "last_analysis": attr.get("last_analysis_date"),
        "malicious_engines": [
            {"engine": k, "result": v.get("result")}
            for k, v in attr.get("last_analysis_results", {}).items()
            if v.get("category") == "malicious"
        ],
    }


def handle_upload_file(args):
    file_path = args.get("file_path")
    wait      = args.get("wait", True)
    key       = get_api_key()

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)

    # Files > 32MB require a special upload URL
    if file_size > 32 * 1024 * 1024:
        url_data = vt_get("files/upload_url")
        upload_url = url_data.get("data")
    else:
        upload_url = "https://www.virustotal.com/api/v3/files"

    with open(file_path, "rb") as f:
        resp = requests.post(
            upload_url,
            headers={"x-apikey": key},
            files={"file": (os.path.basename(file_path), f)},
            timeout=120,
        )
    resp.raise_for_status()
    analysis_id = resp.json().get("data", {}).get("id")

    if not wait:
        return {"analysis_id": analysis_id, "status": "queued"}

    # Poll until analysis is complete (max 2 minutes)
    for _ in range(24):
        time.sleep(5)
        result = vt_get(f"analyses/{analysis_id}")
        status = result.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            attr  = result.get("data", {}).get("attributes", {})
            stats = parse_stats(attr.get("stats", {}))
            return {
                "file":      os.path.basename(file_path),
                "size":      file_size,
                "stats":     stats,
                "verdict":   "malicious" if stats["malicious"] > 0 else "suspicious" if stats["suspicious"] > 0 else "clean",
                "malicious_engines": [
                    {"engine": k, "result": v.get("result")}
                    for k, v in attr.get("results", {}).items()
                    if v.get("category") == "malicious"
                ],
                "analysis_id": analysis_id,
            }

    return {"analysis_id": analysis_id, "status": "timeout — use vt_scan_hash to check later"}


def handle_get_comments(args):
    rtype = args.get("resource_type")
    rid   = args.get("resource_id")
    import base64
    if rtype == "urls":
        rid = base64.urlsafe_b64encode(rid.encode()).decode().rstrip("=")
    data = vt_get(f"{rtype}/{rid}/comments", {"limit": 5})
    return [
        {
            "date":  c.get("attributes", {}).get("date"),
            "text":  c.get("attributes", {}).get("text"),
            "votes": c.get("attributes", {}).get("votes"),
        }
        for c in data.get("data", [])
    ]


HANDLERS = {
    "vt_scan_ip":       handle_scan_ip,
    "vt_scan_domain":   handle_scan_domain,
    "vt_scan_url":      handle_scan_url,
    "vt_scan_hash":     handle_scan_hash,
    "vt_upload_file":   handle_upload_file,
    "vt_get_comments":  handle_get_comments,
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
                "serverInfo": {"name": "virustotal-mcp", "version": "1.0.0"},
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
