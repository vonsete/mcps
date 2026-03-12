# MCP Servers

Collection of 33 standalone MCP (Model Context Protocol) servers written in Python, plus the **RedTool** recon framework. Each server exposes tools to Claude via JSON-RPC 2.0 over stdin/stdout.

## Servers

### Threat Intelligence Platform
| Server | Description |
|--------|-------------|
| `misp_mcp_server.py` | MISP: search events/attributes, IOC lookup, create events, manage feeds and tags |

### Security Intelligence
| Server | Description |
|--------|-------------|
| `shodan_mcp_server.py` | Host search, port lookup, ASN info |
| `virustotal_mcp_server.py` | IP, domain, URL, file hash analysis |
| `abuseipdb_mcp_server.py` | IP abuse reports and blacklist |
| `greynoise_mcp_server.py` | Internet scanner classification |
| `maltiverse_mcp_server.py` | Threat intelligence for IPs, domains, URLs, hashes |
| `criminalip_mcp_server.py` | IP/domain scoring, VPN/proxy detection |
| `otx_mcp_server.py` | AlienVault OTX pulses and indicators |
| `pulsedive_mcp_server.py` | Threat feeds and indicator lookup |
| `securitytrails_mcp_server.py` | DNS history, subdomains, WHOIS history |
| `abusech_mcp_server.py` | MalwareBazaar, URLhaus, ThreatFox |
| `censys_mcp_server.py` | Host and certificate search |

### Network / Recon
| Server | Description |
|--------|-------------|
| `dns_mcp_server.py` | DNS lookup, SPF, DMARC, DKIM, full audit |
| `bgp_mcp_server.py` | ASN info, prefixes, BGP peers |
| `whois_mcp_server.py` | Domain and IP WHOIS |
| `traceroute_mcp_server.py` | Traceroute, MTR, ping |
| `nmap_mcp_server.py` | Port scan, service fingerprint, OS detection |
| `ssl_mcp_server.py` | Certificate check, expiry, TLS protocols |
| `geoip_mcp_server.py` | IP geolocation, bulk lookup |
| `httpheaders_mcp_server.py` | Security headers, HTTP requests, redirect tracing |
| `crtsh_mcp_server.py` | Certificate Transparency log search |
| `urlscan_mcp_server.py` | URL scan and search |

### Infrastructure Management
| Server | Description |
|--------|-------------|
| `unifi_mcp_server.py` | UniFi controller: devices, clients, firewall, VLANs |
| `mikrotik_mcp_server.py` | MikroTik RouterOS: interfaces, firewall, DHCP, routing |
| `snmp_mcp_server.py` | SNMP v1/v2c: system info, interfaces, ARP, routing (pure Python BER/ASN.1) |
| `ufw_mcp_server.py` | UFW firewall rules management |
| `cloudflare_mcp_server.py` | Zones, DNS records, WAF, cache, analytics |
| `ssh_mcp_server.py` | Remote command execution (static key + Vault signed certs) |

### Vulnerability / Threat Analysis
| Server | Description |
|--------|-------------|
| `cve_mcp_server.py` | CVE lookup and search (NVD) |
| `nuclei_mcp_server.py` | Nuclei vulnerability scanner |
| `hybridanalysis_mcp_server.py` | Sandbox analysis, IOC extraction |

### Data / Productivity
| Server | Description |
|--------|-------------|
| `db_mcp_server.py` | Read-only SQL queries (PostgreSQL, MySQL, SQLite, SQL Server, Oracle) |
| `jira_mcp_server.py` | Issues, transitions, comments |
| `anythingllm_mcp_server.py` | RAG workspace chat and document management |
| `gdrive_mcp_server.py` | Google Drive file listing and reading |

## RedTool

Modular recon framework at `redtool/`.

```
redtool/
├── redtool.py          # Entry point
├── core/
│   ├── console.py      # Interactive console
│   ├── module_loader.py
│   ├── output.py
│   └── session.py
└── modules/
    └── recon/
        ├── banner_grab.py
        ├── dns_enum.py
        ├── ping_sweep.py
        └── portscan.py
```

```bash
python3 redtool/redtool.py
python3 redtool/redtool.py --no-banner --module redtool/modules/recon/portscan.py
```

## Running a Server

```bash
python3 shodan_mcp_server.py
```

No build step. Install dependencies as needed:

```bash
pip install requests dnspython paramiko psycopg2 pymysql librouteros
```

## Credentials

Each server loads credentials in this order:

1. Environment variable (e.g. `SHODAN_API_KEY`)
2. `~/.{service}_key` file — plain value, `KEY=value`, or JSON object

## Architecture

All servers follow the same structure:

- **JSON-RPC 2.0** over stdin/stdout
- **Protocol version**: `2024-11-05`
- **Tool responses**: `{"content": [{"type": "text", "text": "..."}]}`
- **Error responses**: `isError: true` with a text message

## MCP Configuration

Servers are registered in `.mcp.json` for use with Claude Code. Example entry:

```json
{
  "mcpServers": {
    "shodan": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/alfonso/mcps/shodan_mcp_server.py"]
    }
  }
}
```
