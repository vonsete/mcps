# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a collection of 32 standalone MCP (Model Context Protocol) servers written in Python. Each server exposes a set of tools to Claude via JSON-RPC 2.0 over stdin/stdout, enabling interaction with security intelligence APIs, network infrastructure, databases, and more.

## Running a Server

Each server is a self-contained script:

```bash
python3 shodan_mcp_server.py   # or any *_mcp_server.py
```

There is no build step. Dependencies are installed per-server via pip:

```bash
pip install requests dnspython paramiko psycopg2 pymysql librouteros
```

## Architecture

All 32 servers follow an identical 5-section template:

1. **Helpers** — `send()`, `respond()`, `error()`, `text_result()`: JSON-RPC serialization
2. **Auth layer** — API key loaded from env var or `~/.{service}_key` file
3. **API/service calls** — HTTP via `requests`, subprocess, or library
4. **TOOLS list** — MCP tool declarations with JSON Schema `inputSchema`
5. **HANDLERS dict** — maps tool names to implementation functions
6. **Main loop** — reads stdin, dispatches on `method`: `initialize`, `tools/list`, `tools/call`

### Tool response format

All tools return:
```python
{"content": [{"type": "text", "text": json.dumps(data, indent=2)}]}
```

On error, `isError: true` is set alongside a text message.

### MCP protocol version

`2024-11-05` — declared in the `initialize` response.

## Credential Pattern

Credentials are loaded in this priority order (per server):
1. Environment variable (e.g. `SHODAN_API_KEY`)
2. `~/.{service}_key` file — plain value, `KEY=value` format, or JSON object

JSON credential files (e.g. `~/.mikrotik_key`, `~/.unifi_key`) store structured config like host/username/password.

## Server Categories

| Category | Servers |
|---|---|
| Security intelligence | shodan, virustotal, abuseipdb, greynoise, maltiverse, criminalip, otx, pulsedive, securitytrails, abusech |
| Network / recon | dns, bgp, whois, traceroute, nmap, ssl, geoip, httpheaders |
| Infrastructure mgmt | unifi, mikrotik, snmp, ufw, cloudflare, ssh |
| Databases | db (PostgreSQL/MySQL/SQLite/SQL Server/Oracle — read-only) |
| Vuln / threat analysis | cve, crtsh, urlscan, nuclei, hybridanalysis |
| Ticketing | jira |

## Adding a New Server

Follow the existing template exactly. Key points:
- Use the same 4 helper functions (`send`, `respond`, `error`, `text_result`) copy-pasted verbatim
- Declare credentials via env var with `~/.{service}_key` fallback
- Register tools in `TOOLS` (JSON Schema) and handlers in `HANDLERS`
- The main loop is identical across all servers — copy it as-is

## `.mcp.json`

Only `ssh-mcp` (an npm package) is declared here; it is invoked via `npx`. All Python servers are registered separately in Claude's MCP configuration (outside this repo).

## Notable Implementations

- **snmp_mcp_server.py** — pure Python BER/ASN.1 encoder/decoder (no external SNMP library)
- **db_mcp_server.py** — multi-engine database explorer; enforces read-only access
- **ssh_mcp_server.py** — supports both static SSH keys and HashiCorp Vault signed certificates
- **unifi_mcp_server.py** — maintains session cookies and CSRF tokens across requests
