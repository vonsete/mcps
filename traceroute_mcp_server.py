#!/usr/bin/env python3
"""
MCP server for Traceroute / MTR network path diagnostics.
Uses system traceroute and mtr commands.
"""

import sys
import json
import subprocess
import re


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


TOOLS = [
    {
        "name": "traceroute",
        "description": "Trace the network path to a host, showing each hop with IP, hostname and RTT.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Target host or IP"},
                "max_hops": {"type": "integer", "description": "Maximum hops (default 30)"},
                "timeout":  {"type": "integer", "description": "Timeout per probe in seconds (default 3)"},
                "protocol": {"type": "string",  "description": "Protocol: icmp, udp, tcp (default udp)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "mtr_report",
        "description": "Run MTR (My Traceroute) — combines traceroute + ping, shows packet loss and jitter per hop.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":    {"type": "string",  "description": "Target host or IP"},
                "cycles":  {"type": "integer", "description": "Number of ping cycles per hop (default 10)"},
                "max_hops":{"type": "integer", "description": "Maximum hops (default 30)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "ping",
        "description": "Ping a host and return packet loss, RTT min/avg/max.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":  {"type": "string",  "description": "Target host or IP"},
                "count": {"type": "integer", "description": "Number of packets (default 5)"},
            },
            "required": ["host"],
        },
    },
]


def parse_traceroute(output):
    hops = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Match lines like: " 1  router.local (192.168.1.1)  1.234 ms  1.100 ms  0.980 ms"
        m = re.match(r'^(\d+)\s+(.*)', line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest    = m.group(2).strip()
        if rest.startswith('*'):
            hops.append({"hop": hop_num, "host": "*", "ip": None, "rtts_ms": []})
            continue
        # Extract hostname/IP
        ip_m = re.search(r'\(([^)]+)\)', rest)
        ip   = ip_m.group(1) if ip_m else None
        # Try to get hostname before the IP
        hostname = rest.split()[0] if rest else None
        if hostname and hostname.startswith('('):
            hostname = ip
        # Extract RTTs
        rtts = [float(x) for x in re.findall(r'([\d.]+)\s*ms', rest)]
        hops.append({
            "hop":     hop_num,
            "host":    hostname,
            "ip":      ip,
            "rtts_ms": rtts,
            "avg_ms":  round(sum(rtts) / len(rtts), 3) if rtts else None,
        })
    return hops


def handle_traceroute(args):
    host     = args["host"]
    max_hops = int(args.get("max_hops", 30))
    timeout  = int(args.get("timeout", 3))
    protocol = args.get("protocol", "udp").lower()

    cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout)]
    if protocol == "icmp":
        cmd.append("-I")
    elif protocol == "tcp":
        cmd += ["-T", "-p", "80"]
    cmd.append(host)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        hops   = parse_traceroute(output)
        return {
            "host":     host,
            "protocol": protocol,
            "max_hops": max_hops,
            "hops":     hops,
            "total_hops": len([h for h in hops if h["ip"]]),
            "raw":      output,
        }
    except FileNotFoundError:
        return {"error": "traceroute not found. Install with: sudo apt install traceroute"}
    except subprocess.TimeoutExpired:
        return {"error": "traceroute timed out"}


def parse_mtr_json(output):
    try:
        data  = json.loads(output)
        hubs  = data.get("report", {}).get("hubs", [])
        return [
            {
                "hop":      h.get("count"),
                "host":     h.get("host"),
                "loss_pct": h.get("Loss%"),
                "sent":     h.get("Snt"),
                "last_ms":  h.get("Last"),
                "avg_ms":   h.get("Avg"),
                "best_ms":  h.get("Best"),
                "worst_ms": h.get("Wrst"),
                "stdev_ms": h.get("StDev"),
            }
            for h in hubs
        ]
    except Exception:
        return []


def handle_mtr_report(args):
    host     = args["host"]
    cycles   = int(args.get("cycles", 10))
    max_hops = int(args.get("max_hops", 30))

    # Try JSON output first
    cmd = ["mtr", "--report", "--json", f"--report-cycles={cycles}", f"--max-ttl={max_hops}", host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and result.stdout.strip():
            hops = parse_mtr_json(result.stdout)
            if hops:
                return {"host": host, "cycles": cycles, "hops": hops}
        # Fallback: plain text report
        cmd2 = ["mtr", "--report", f"--report-cycles={cycles}", f"--max-ttl={max_hops}", host]
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=120)
        return {"host": host, "cycles": cycles, "raw": result2.stdout or result2.stderr}
    except FileNotFoundError:
        return {"error": "mtr not found. Install with: sudo apt install mtr-tiny"}
    except subprocess.TimeoutExpired:
        return {"error": "mtr timed out"}


def handle_ping(args):
    host  = args["host"]
    count = int(args.get("count", 5))
    cmd   = ["ping", "-c", str(count), "-W", "3", host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        # Parse summary line: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms
        rtt_m = re.search(r'rtt [^=]+=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        loss_m = re.search(r'(\d+)%\s+packet loss', output)
        recv_m = re.search(r'(\d+) received', output)
        return {
            "host":      host,
            "count":     count,
            "received":  int(recv_m.group(1)) if recv_m else None,
            "loss_pct":  int(loss_m.group(1)) if loss_m else None,
            "rtt_min_ms": float(rtt_m.group(1)) if rtt_m else None,
            "rtt_avg_ms": float(rtt_m.group(2)) if rtt_m else None,
            "rtt_max_ms": float(rtt_m.group(3)) if rtt_m else None,
            "rtt_mdev_ms": float(rtt_m.group(4)) if rtt_m else None,
            "reachable": result.returncode == 0,
            "raw": output,
        }
    except FileNotFoundError:
        return {"error": "ping not found"}
    except subprocess.TimeoutExpired:
        return {"error": "ping timed out"}


HANDLERS = {
    "traceroute":  handle_traceroute,
    "mtr_report":  handle_mtr_report,
    "ping":        handle_ping,
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
                "serverInfo": {"name": "traceroute-mcp", "version": "1.0.0"},
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
