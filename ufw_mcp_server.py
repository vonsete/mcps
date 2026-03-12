#!/usr/bin/env python3
"""
MCP server for UFW (Uncomplicated Firewall) management.
Executes ufw commands via SSH on a remote host, or locally if no host given.
SSH key from ~/.ssh/id_rsa (or specify key_path per call).
"""

import sys
import json
import os
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


def run_cmd(cmd, host=None, user="root", port=22, key_path=None):
    """Run a command locally or via SSH. Returns (stdout, stderr, returncode)."""
    if host:
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                   "-p", str(port)]
        if key_path:
            ssh_cmd += ["-i", key_path]
        ssh_cmd += [f"{user}@{host}", cmd]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
    else:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return result.stdout, result.stderr, result.returncode


def run_ufw(subcmd, host=None, user="root", port=22, key_path=None):
    """Run a ufw command with sudo, return output."""
    cmd = f"sudo ufw {subcmd}"
    stdout, stderr, rc = run_cmd(cmd, host, user, port, key_path)
    output = (stdout + stderr).strip()
    return output, rc


def conn_args(args):
    return {
        "host":     args.get("host"),
        "user":     args.get("user", "root"),
        "port":     int(args.get("port", 22)),
        "key_path": args.get("key_path"),
    }


TOOLS = [
    {
        "name": "ufw_status",
        "description": "Show UFW status: enabled/disabled, all rules with rule numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
    {
        "name": "ufw_enable",
        "description": "Enable UFW firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
    {
        "name": "ufw_disable",
        "description": "Disable UFW firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
    {
        "name": "ufw_allow",
        "description": "Add an ALLOW rule. Examples: port 22, port range 8000:8100, app 'Nginx Full', from IP to port.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule":     {"type": "string",  "description": "Rule spec, e.g. '22/tcp', '80', 'Nginx Full', 'from 1.2.3.4 to any port 22'"},
                "comment":  {"type": "string",  "description": "Optional comment for the rule"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["rule"],
        },
    },
    {
        "name": "ufw_deny",
        "description": "Add a DENY rule.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule":     {"type": "string",  "description": "Rule spec, e.g. '23', 'from 1.2.3.4'"},
                "comment":  {"type": "string",  "description": "Optional comment for the rule"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["rule"],
        },
    },
    {
        "name": "ufw_reject",
        "description": "Add a REJECT rule (sends TCP reset/ICMP unreachable instead of dropping silently).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule":     {"type": "string",  "description": "Rule spec"},
                "comment":  {"type": "string",  "description": "Optional comment"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["rule"],
        },
    },
    {
        "name": "ufw_limit",
        "description": "Add a rate-limit rule (blocks IPs with >6 connections in 30s). Useful for SSH brute-force protection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule":     {"type": "string",  "description": "Port/service, e.g. '22/tcp', 'ssh'"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["rule"],
        },
    },
    {
        "name": "ufw_delete",
        "description": "Delete a rule by rule number (get numbers from ufw_status) or by rule spec.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_number": {"type": "integer", "description": "Rule number from 'ufw status numbered'"},
                "rule_spec":   {"type": "string",  "description": "Rule spec to delete, e.g. 'allow 80' (alternative to rule_number)"},
                "host":        {"type": "string",  "description": "Remote host (omit for local)"},
                "user":        {"type": "string",  "description": "SSH user (default: root)"},
                "port":        {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path":    {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
    {
        "name": "ufw_reset",
        "description": "Reset UFW to defaults (disables UFW and deletes all rules). Use with caution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
    {
        "name": "ufw_default",
        "description": "Set default policy for incoming, outgoing, or routed traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "policy":    {"type": "string", "description": "Policy: allow, deny, reject"},
                "direction": {"type": "string", "description": "Direction: incoming, outgoing, routed (default: incoming)"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["policy"],
        },
    },
    {
        "name": "ufw_app_list",
        "description": "List available UFW application profiles (Nginx, OpenSSH, Apache, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
    {
        "name": "ufw_app_info",
        "description": "Show details of a UFW application profile (ports, description).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app":      {"type": "string",  "description": "Application profile name, e.g. 'Nginx Full'"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["app"],
        },
    },
    {
        "name": "ufw_logging",
        "description": "Set UFW logging level: on (low), medium, high, full, or off.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "level":    {"type": "string",  "description": "Logging level: off, on, low, medium, high, full"},
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
            "required": ["level"],
        },
    },
    {
        "name": "ufw_show_raw",
        "description": "Show underlying iptables rules (raw) for advanced inspection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":     {"type": "string",  "description": "Remote host (omit for local)"},
                "user":     {"type": "string",  "description": "SSH user (default: root)"},
                "port":     {"type": "integer", "description": "SSH port (default: 22)"},
                "key_path": {"type": "string",  "description": "Path to SSH private key"},
            },
        },
    },
]


def parse_status(raw):
    """Parse 'ufw status numbered' output into structured data."""
    lines  = raw.splitlines()
    status = "inactive"
    rules  = []
    for line in lines:
        if line.startswith("Status:"):
            status = line.split(":", 1)[1].strip()
        # Match numbered rules like: [ 1] 22/tcp ALLOW IN Anywhere
        m = re.match(r'\[\s*(\d+)\]\s+(.+)', line)
        if m:
            num      = int(m.group(1))
            rest     = m.group(2).strip()
            # Split into columns (to, action, from)
            parts    = re.split(r'\s{2,}', rest)
            rules.append({
                "num":    num,
                "raw":    rest,
                "to":     parts[0] if len(parts) > 0 else "",
                "action": parts[1] if len(parts) > 1 else "",
                "from":   parts[2] if len(parts) > 2 else "Anywhere",
            })
    return {"status": status, "rules": rules, "rule_count": len(rules)}


def handle_ufw_status(args):
    c = conn_args(args)
    out, rc = run_ufw("status numbered", **c)
    parsed = parse_status(out)
    parsed["raw"] = out
    return parsed


def handle_ufw_enable(args):
    c = conn_args(args)
    # Use 'yes |' to auto-confirm the prompt
    cmd = "sudo sh -c 'yes | ufw enable'"
    stdout, stderr, rc = run_cmd(cmd, **c)
    return {"output": (stdout + stderr).strip(), "success": rc == 0}


def handle_ufw_disable(args):
    c = conn_args(args)
    out, rc = run_ufw("disable", **c)
    return {"output": out, "success": rc == 0}


def _action_rule(action, args):
    c    = conn_args(args)
    rule = args["rule"]
    cmd  = f"{action} {rule}"
    comment = args.get("comment", "")
    if comment:
        cmd += f" comment '{comment}'"
    out, rc = run_ufw(cmd, **c)
    return {"output": out, "success": rc == 0, "action": action, "rule": rule}


def handle_ufw_allow(args):
    return _action_rule("allow", args)

def handle_ufw_deny(args):
    return _action_rule("deny", args)

def handle_ufw_reject(args):
    return _action_rule("reject", args)

def handle_ufw_limit(args):
    c    = conn_args(args)
    rule = args["rule"]
    out, rc = run_ufw(f"limit {rule}", **c)
    return {"output": out, "success": rc == 0, "rule": rule}


def handle_ufw_delete(args):
    c = conn_args(args)
    if "rule_number" in args:
        # Echo 'y' to confirm deletion
        cmd = f"echo y | sudo ufw delete {args['rule_number']}"
        stdout, stderr, rc = run_cmd(cmd, **c)
        out = (stdout + stderr).strip()
    elif "rule_spec" in args:
        cmd = f"echo y | sudo ufw delete {args['rule_spec']}"
        stdout, stderr, rc = run_cmd(cmd, **c)
        out = (stdout + stderr).strip()
    else:
        return {"error": "Provide rule_number or rule_spec"}
    return {"output": out, "success": rc == 0}


def handle_ufw_reset(args):
    c = conn_args(args)
    cmd = "echo y | sudo ufw reset"
    stdout, stderr, rc = run_cmd(cmd, **c)
    return {"output": (stdout + stderr).strip(), "success": rc == 0}


def handle_ufw_default(args):
    c         = conn_args(args)
    policy    = args["policy"]
    direction = args.get("direction", "incoming")
    out, rc   = run_ufw(f"default {policy} {direction}", **c)
    return {"output": out, "success": rc == 0, "policy": policy, "direction": direction}


def handle_ufw_app_list(args):
    c      = conn_args(args)
    out, _ = run_ufw("app list", **c)
    apps   = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("Available")]
    return {"apps": apps, "raw": out}


def handle_ufw_app_info(args):
    c    = conn_args(args)
    app  = args["app"]
    out, rc = run_ufw(f"app info '{app}'", **c)
    info = {"app": app, "raw": out}
    for line in out.splitlines():
        if line.startswith("Title:"):
            info["title"] = line.split(":", 1)[1].strip()
        elif line.startswith("Description:"):
            info["description"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ports:"):
            info["ports"] = line.split(":", 1)[1].strip()
    return info


def handle_ufw_logging(args):
    c     = conn_args(args)
    level = args["level"]
    out, rc = run_ufw(f"logging {level}", **c)
    return {"output": out, "success": rc == 0, "level": level}


def handle_ufw_show_raw(args):
    c   = conn_args(args)
    out, rc = run_ufw("show raw", **c)
    return {"output": out, "success": rc == 0}


HANDLERS = {
    "ufw_status":   handle_ufw_status,
    "ufw_enable":   handle_ufw_enable,
    "ufw_disable":  handle_ufw_disable,
    "ufw_allow":    handle_ufw_allow,
    "ufw_deny":     handle_ufw_deny,
    "ufw_reject":   handle_ufw_reject,
    "ufw_limit":    handle_ufw_limit,
    "ufw_delete":   handle_ufw_delete,
    "ufw_reset":    handle_ufw_reset,
    "ufw_default":  handle_ufw_default,
    "ufw_app_list": handle_ufw_app_list,
    "ufw_app_info": handle_ufw_app_info,
    "ufw_logging":  handle_ufw_logging,
    "ufw_show_raw": handle_ufw_show_raw,
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
                "serverInfo": {"name": "ufw-mcp", "version": "1.0.0"},
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
