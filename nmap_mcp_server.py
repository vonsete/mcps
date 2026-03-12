#!/usr/bin/env python3
"""
MCP server for Nmap network scanning.
Provides dynamic host/port/option scanning without hardcoded targets.
"""

import sys
import json
import subprocess


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


def run_nmap(args, timeout=120):
    """Run nmap with given args and return stdout+stderr."""
    cmd = ["nmap"] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = result.stdout
    if result.stderr:
        out += f"\n[stderr]: {result.stderr}"
    return out or "(no output)"


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "nmap_scan",
        "description": (
            "Run a flexible Nmap scan against one or more hosts. "
            "Supports port ranges, service/version detection, OS detection, scripts and timing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Host, IP, or CIDR range to scan (e.g. 192.168.1.1, 192.168.1.0/24, scanme.nmap.org)",
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to scan (e.g. '22,80,443', '1-1024', '-' for all). Omit for default top 1000.",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["sT", "sS", "sU", "sn"],
                    "description": "Scan type: sT=TCP connect (no root), sS=SYN stealth (root), sU=UDP (root), sn=ping only. Default: sT.",
                },
                "service_version": {
                    "type": "boolean",
                    "description": "Detect service versions (-sV). Default: false.",
                },
                "os_detect": {
                    "type": "boolean",
                    "description": "Enable OS detection (-O, requires root). Default: false.",
                },
                "scripts": {
                    "type": "string",
                    "description": "Nmap scripts to run (e.g. 'default', 'vuln', 'banner,ssh-hostkey'). Default: none.",
                },
                "timing": {
                    "type": "integer",
                    "description": "Timing template 0-5 (0=paranoid, 3=normal, 5=insane). Default: 3.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional raw nmap arguments (e.g. '--open --traceroute').",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "nmap_ping_sweep",
        "description": "Quick host discovery (ping sweep) on a network range. No port scanning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Network range to sweep (e.g. 192.168.1.0/24)",
                },
                "timing": {
                    "type": "integer",
                    "description": "Timing template 0-5. Default: 4.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "nmap_service_fingerprint",
        "description": "Deep service and version fingerprinting on specific ports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Host or IP to fingerprint",
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to fingerprint (e.g. '22,80,443'). Required.",
                },
            },
            "required": ["target", "ports"],
        },
    },
]


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def handle_nmap_scan(args):
    target          = args.get("target")
    ports           = args.get("ports")
    scan_type       = args.get("scan_type", "sT")
    service_version = args.get("service_version", False)
    os_detect       = args.get("os_detect", False)
    scripts         = args.get("scripts")
    timing          = args.get("timing", 3)
    extra_args      = args.get("extra_args", "")

    cmd = [f"-{scan_type}", f"-T{timing}", target]

    if ports:
        cmd += ["-p", ports]
    if service_version:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")
    if scripts:
        cmd += ["--script", scripts]
    if extra_args:
        cmd += extra_args.split()

    return run_nmap(cmd)


def handle_ping_sweep(args):
    target  = args.get("target")
    timing  = args.get("timing", 4)
    return run_nmap(["-sn", f"-T{timing}", target])


def handle_service_fingerprint(args):
    target = args.get("target")
    ports  = args.get("ports")
    return run_nmap(["-sV", "--version-intensity", "9", "-p", ports, target])


def handle_call(id, name, args):
    try:
        if name == "nmap_scan":
            text = handle_nmap_scan(args)
        elif name == "nmap_ping_sweep":
            text = handle_ping_sweep(args)
        elif name == "nmap_service_fingerprint":
            text = handle_service_fingerprint(args)
        else:
            error(id, -32601, f"Unknown tool: {name}")
            return

        respond(id, {"content": [{"type": "text", "text": text}]})

    except subprocess.TimeoutExpired:
        respond(id, {"content": [{"type": "text", "text": "[error]: nmap timed out"}], "isError": True})
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
                "serverInfo": {"name": "nmap-mcp", "version": "1.0.0"},
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
