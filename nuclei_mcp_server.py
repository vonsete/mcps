#!/usr/bin/env python3
"""
MCP server for Nuclei — fast vulnerability scanner using templates.
Requires nuclei installed: https://github.com/projectdiscovery/nuclei
Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
     or: sudo apt install nuclei  (Kali/Ubuntu)

Nuclei runs locally or via SSH on a remote host.
"""

import sys
import json
import os
import subprocess
import re
import tempfile


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


def find_nuclei():
    """Find nuclei binary."""
    for path in [
        "/usr/bin/nuclei",
        "/usr/local/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/.local/bin/nuclei"),
    ]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # Try which
    try:
        result = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    raise RuntimeError("nuclei not found. Install it: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")


def run_nuclei(cmd_args, timeout=300):
    """Run nuclei command, return stdout lines."""
    nuclei = find_nuclei()
    cmd    = [nuclei] + cmd_args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout, result.stderr, result.returncode


def parse_jsonl_output(text):
    """Parse nuclei JSONL output (-je flag)."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


def fmt_finding(f):
    info = f.get("info", {})
    return {
        "template_id":  f.get("template-id"),
        "name":         info.get("name"),
        "severity":     info.get("severity"),
        "type":         f.get("type"),
        "host":         f.get("host"),
        "matched_at":   f.get("matched-at"),
        "description":  info.get("description", "")[:200] if info.get("description") else None,
        "tags":         info.get("tags", []),
        "reference":    info.get("reference", [])[:3],
        "cvss_score":   (info.get("classification") or {}).get("cvss-score"),
        "cve_id":       (info.get("classification") or {}).get("cve-id", []),
        "cwe_id":       (info.get("classification") or {}).get("cwe-id", []),
        "extracted":    f.get("extracted-results", [])[:5],
        "curl_command": f.get("curl-command"),
        "timestamp":    (f.get("timestamp") or "")[:19] or None,
    }


TOOLS = [
    {
        "name": "nuclei_scan",
        "description": "Run a Nuclei vulnerability scan against one or more targets. Supports filtering by severity, tags, or template IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets":    {"type": "array",  "items": {"type": "string"}, "description": "List of targets: URLs, IPs, domains, CIDRs"},
                "target":     {"type": "string", "description": "Single target (alternative to targets list)"},
                "severity":   {"type": "string", "description": "Severity filter: critical,high,medium,low,info (comma-separated, default: critical,high,medium)"},
                "tags":       {"type": "string", "description": "Template tags to include (e.g. 'cve,rce,sqli')"},
                "templates":  {"type": "array",  "items": {"type": "string"}, "description": "Specific template IDs or paths"},
                "exclude_tags":{"type": "string","description": "Tags to exclude (e.g. 'intrusive,dos')"},
                "rate_limit": {"type": "integer","description": "Max requests per second (default 150)"},
                "timeout":    {"type": "integer","description": "Scan timeout in seconds (default 120)"},
                "proxy":      {"type": "string", "description": "HTTP proxy URL (optional)"},
            },
        },
    },
    {
        "name": "nuclei_scan_cves",
        "description": "Scan a target specifically for known CVEs using Nuclei CVE templates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":   {"type": "string",  "description": "Target URL, IP, or domain"},
                "year":     {"type": "integer", "description": "Filter CVEs by year (e.g. 2024)"},
                "severity": {"type": "string",  "description": "Severity filter (default: critical,high)"},
                "timeout":  {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_scan_tech",
        "description": "Detect technologies, panels, login pages, and exposed services on a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":  {"type": "string",  "description": "Target URL, IP, or domain"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_templates",
        "description": "List available Nuclei templates, optionally filtered by tag or severity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag":      {"type": "string", "description": "Filter by tag (e.g. 'cve', 'rce', 'sqli', 'xss')"},
                "severity": {"type": "string", "description": "Filter by severity"},
                "search":   {"type": "string", "description": "Search in template ID or name"},
            },
        },
    },
    {
        "name": "nuclei_update",
        "description": "Update Nuclei templates to the latest version.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "nuclei_version",
        "description": "Show installed Nuclei version and template stats.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def handle_nuclei_scan(args):
    targets = args.get("targets", [])
    if not targets and "target" in args:
        targets = [args["target"]]
    if not targets:
        return {"error": "Provide target or targets"}

    severity    = args.get("severity", "critical,high,medium")
    rate_limit  = int(args.get("rate_limit", 150))
    timeout_sec = int(args.get("timeout", 120))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        target_file = tf.name

    try:
        cmd = [
            "-l", target_file,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-timeout", "5",
            "-je",        # JSON lines output
            "-silent",
            "-no-color",
        ]
        if "tags" in args:
            cmd += ["-tags", args["tags"]]
        if "exclude_tags" in args:
            cmd += ["-exclude-tags", args["exclude_tags"]]
        if "templates" in args:
            for t in args["templates"]:
                cmd += ["-t", t]
        if "proxy" in args:
            cmd += ["-proxy", args["proxy"]]

        stdout, stderr, rc = run_nuclei(cmd, timeout=timeout_sec + 30)
        findings = parse_jsonl_output(stdout)

        by_severity = {}
        for f in findings:
            sev = (f.get("info", {}).get("severity") or "info").lower()
            by_severity.setdefault(sev, []).append(fmt_finding(f))

        return {
            "targets":     targets,
            "severity_filter": severity,
            "total_findings": len(findings),
            "summary": {s: len(v) for s, v in by_severity.items()},
            "findings_by_severity": by_severity,
        }
    finally:
        os.unlink(target_file)


def handle_nuclei_scan_cves(args):
    target   = args["target"]
    severity = args.get("severity", "critical,high")
    timeout_sec = int(args.get("timeout", 120))

    cmd = [
        "-u", target,
        "-tags", "cve",
        "-severity", severity,
        "-je", "-silent", "-no-color",
        "-timeout", "5",
    ]
    if "year" in args:
        cmd += ["-tags", f"cve,{args['year']}"]

    stdout, stderr, rc = run_nuclei(cmd, timeout=timeout_sec + 30)
    findings = parse_jsonl_output(stdout)

    return {
        "target":         target,
        "total_cve_findings": len(findings),
        "findings": [fmt_finding(f) for f in findings],
    }


def handle_nuclei_scan_tech(args):
    target      = args["target"]
    timeout_sec = int(args.get("timeout", 60))

    cmd = [
        "-u", target,
        "-tags", "tech,panel,login,detect,exposure",
        "-severity", "info,low,medium,high,critical",
        "-je", "-silent", "-no-color",
        "-timeout", "5",
    ]
    stdout, stderr, rc = run_nuclei(cmd, timeout=timeout_sec + 30)
    findings = parse_jsonl_output(stdout)

    return {
        "target":       target,
        "total":        len(findings),
        "technologies": [fmt_finding(f) for f in findings],
    }


def handle_nuclei_templates(args):
    cmd = ["-tl", "-silent"]
    stdout, stderr, rc = run_nuclei(cmd, timeout=30)

    lines   = [l.strip() for l in stdout.splitlines() if l.strip()]
    tag     = (args.get("tag") or "").lower()
    sev     = (args.get("severity") or "").lower()
    search  = (args.get("search") or "").lower()

    # Filter
    if tag or sev or search:
        filtered = []
        for line in lines:
            ll = line.lower()
            if tag and tag not in ll:
                continue
            if search and search not in ll:
                continue
            filtered.append(line)
        lines = filtered

    return {
        "count":     len(lines),
        "templates": lines[:200],
    }


def handle_nuclei_update(args):
    stdout, stderr, rc = run_nuclei(["-update-templates", "-silent"], timeout=120)
    return {
        "success": rc == 0,
        "output":  (stdout + stderr).strip()[:500],
    }


def handle_nuclei_version(args):
    stdout, stderr, rc = run_nuclei(["-version"], timeout=10)
    output = (stdout + stderr).strip()

    # Parse template stats
    stats_out, _, _ = run_nuclei(["-stats", "-duration", "1s", "-u", "localhost", "-silent"], timeout=5)

    return {
        "version": output,
        "binary":  find_nuclei(),
    }


HANDLERS = {
    "nuclei_scan":      handle_nuclei_scan,
    "nuclei_scan_cves": handle_nuclei_scan_cves,
    "nuclei_scan_tech": handle_nuclei_scan_tech,
    "nuclei_templates": handle_nuclei_templates,
    "nuclei_update":    handle_nuclei_update,
    "nuclei_version":   handle_nuclei_version,
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
                "serverInfo": {"name": "nuclei-mcp", "version": "1.0.0"},
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
