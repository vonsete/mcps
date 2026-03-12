#!/usr/bin/env python3
"""
MCP server for dynamic SSH connections.
Supports static key auth and HashiCorp Vault CA signed certificates.
"""

import sys
import json
import os
import subprocess
import tempfile
import paramiko
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


def make_text(out, err, exit_code):
    text = out
    if err:
        text += f"\n[stderr]: {err}"
    if exit_code != 0:
        text += f"\n[exit code: {exit_code}]"
    return text or "(no output)"


# ---------------------------------------------------------------------------
# Static key SSH
# ---------------------------------------------------------------------------

def ssh_run(host, user, key, command, port=22, sudo_password=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=user,
                       key_filename=key, timeout=10)
        if sudo_password:
            stdin, stdout, stderr = client.exec_command(
                f"sudo -S {command}", get_pty=True)
            stdin.write(sudo_password + "\n")
            stdin.flush()
        else:
            stdin, stdout, stderr = client.exec_command(command)

        out = stdout.read().decode()
        err = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        return out, err, exit_code
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Vault SSH signed certificates
# ---------------------------------------------------------------------------

def vault_sign_key(vault_addr, vault_token, vault_mount, vault_role, public_key_path, ttl=None):
    """Ask Vault to sign the public key and return the signed certificate."""
    with open(public_key_path) as f:
        public_key = f.read().strip()

    url = f"{vault_addr.rstrip('/')}/v1/{vault_mount}/sign/{vault_role}"
    payload = {"public_key": public_key}
    if ttl:
        payload["ttl"] = ttl

    resp = requests.post(
        url,
        headers={"X-Vault-Token": vault_token, "Content-Type": "application/json"},
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["data"]["signed_key"]


def ssh_run_with_cert(host, user, private_key_path, signed_cert, command,
                      port=22, sudo=False, sudo_password=None):
    """SSH using a Vault-signed certificate via system ssh binary."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Symlink the private key so ssh can find cert automatically
        key_link = os.path.join(tmpdir, "id_key")
        os.symlink(os.path.abspath(private_key_path), key_link)

        # Write the signed cert next to the key (ssh convention: key-cert.pub)
        cert_path = key_link + "-cert.pub"
        with open(cert_path, "w") as f:
            f.write(signed_cert)

        if sudo and sudo_password:
            full_command = f"echo {sudo_password!r} | sudo -S {command}"
        elif sudo:
            full_command = f"sudo {command}"
        else:
            full_command = command

        result = subprocess.run(
            [
                "ssh",
                "-i", key_link,
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(port),
                f"{user}@{host}",
                full_command,
            ],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout, result.stderr, result.returncode


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "ssh_exec",
        "description": "Execute a command on a remote server via SSH using a static private key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":    {"type": "string",  "description": "Remote hostname or IP"},
                "user":    {"type": "string",  "description": "SSH username"},
                "key":     {"type": "string",  "description": "Path to private key file"},
                "command": {"type": "string",  "description": "Command to execute"},
                "port":    {"type": "integer", "description": "SSH port (default 22)"},
            },
            "required": ["host", "user", "key", "command"],
        },
    },
    {
        "name": "ssh_sudo_exec",
        "description": "Execute a command with sudo on a remote server via SSH using a static private key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":          {"type": "string",  "description": "Remote hostname or IP"},
                "user":          {"type": "string",  "description": "SSH username"},
                "key":           {"type": "string",  "description": "Path to private key file"},
                "command":       {"type": "string",  "description": "Command to execute with sudo"},
                "port":          {"type": "integer", "description": "SSH port (default 22)"},
                "sudo_password": {"type": "string",  "description": "Sudo password (if required)"},
            },
            "required": ["host", "user", "key", "command"],
        },
    },
    {
        "name": "ssh_vault_exec",
        "description": (
            "Execute a command on a remote server via SSH using a short-lived certificate "
            "signed by HashiCorp Vault. Vault acts as the SSH CA — no static authorized_keys needed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":            {"type": "string",  "description": "Remote hostname or IP"},
                "user":            {"type": "string",  "description": "SSH username"},
                "private_key":     {"type": "string",  "description": "Path to your private key"},
                "public_key":      {"type": "string",  "description": "Path to your public key to sign"},
                "command":         {"type": "string",  "description": "Command to execute"},
                "vault_addr":      {"type": "string",  "description": "Vault server URL (e.g. https://vault.company.com)"},
                "vault_token":     {"type": "string",  "description": "Vault authentication token"},
                "vault_role":      {"type": "string",  "description": "Vault SSH role name"},
                "vault_mount":     {"type": "string",  "description": "Vault SSH mount path (default: ssh)"},
                "ttl":             {"type": "string",  "description": "Certificate TTL (e.g. 1h, 30m). Defaults to role's ttl. Cannot exceed max_ttl."},
                "port":            {"type": "integer", "description": "SSH port (default 22)"},
            },
            "required": ["host", "user", "private_key", "public_key", "command",
                         "vault_addr", "vault_token", "vault_role"],
        },
    },
    {
        "name": "ssh_vault_sudo_exec",
        "description": (
            "Execute a command with sudo on a remote server via SSH using a Vault-signed certificate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host":            {"type": "string",  "description": "Remote hostname or IP"},
                "user":            {"type": "string",  "description": "SSH username"},
                "private_key":     {"type": "string",  "description": "Path to your private key"},
                "public_key":      {"type": "string",  "description": "Path to your public key to sign"},
                "command":         {"type": "string",  "description": "Command to execute with sudo"},
                "vault_addr":      {"type": "string",  "description": "Vault server URL"},
                "vault_token":     {"type": "string",  "description": "Vault authentication token"},
                "vault_role":      {"type": "string",  "description": "Vault SSH role name"},
                "vault_mount":     {"type": "string",  "description": "Vault SSH mount path (default: ssh)"},
                "ttl":             {"type": "string",  "description": "Certificate TTL (e.g. 1h, 30m). Defaults to role's ttl. Cannot exceed max_ttl."},
                "port":            {"type": "integer", "description": "SSH port (default 22)"},
                "sudo_password":   {"type": "string",  "description": "Sudo password (if required)"},
            },
            "required": ["host", "user", "private_key", "public_key", "command",
                         "vault_addr", "vault_token", "vault_role"],
        },
    },
]


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def handle_call(id, name, args):
    try:
        if name in ("ssh_exec", "ssh_sudo_exec"):
            host    = args.get("host")
            user    = args.get("user")
            key     = args.get("key")
            command = args.get("command")
            port    = args.get("port", 22)
            if not all([host, user, key, command]):
                error(id, -32602, "Missing required parameters: host, user, key, command")
                return
            sudo_password = args.get("sudo_password") if name == "ssh_sudo_exec" else None
            out, err, exit_code = ssh_run(host, user, key, command, port, sudo_password)
            respond(id, {"content": [{"type": "text", "text": make_text(out, err, exit_code)}]})

        elif name in ("ssh_vault_exec", "ssh_vault_sudo_exec"):
            host          = args.get("host")
            user          = args.get("user")
            private_key   = args.get("private_key")
            public_key    = args.get("public_key")
            command       = args.get("command")
            vault_addr    = args.get("vault_addr")
            vault_token   = args.get("vault_token")
            vault_role    = args.get("vault_role")
            vault_mount   = args.get("vault_mount", "ssh")
            ttl           = args.get("ttl")
            port          = args.get("port", 22)
            sudo          = name == "ssh_vault_sudo_exec"
            sudo_password = args.get("sudo_password")

            signed_cert = vault_sign_key(
                vault_addr, vault_token, vault_mount, vault_role, public_key, ttl)

            out, err, exit_code = ssh_run_with_cert(
                host, user, private_key, signed_cert, command, port, sudo, sudo_password)

            respond(id, {"content": [{"type": "text", "text": make_text(out, err, exit_code)}]})

        else:
            error(id, -32601, f"Unknown tool: {name}")

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
                "serverInfo": {"name": "ssh-mcp-dynamic", "version": "2.0.0"},
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
