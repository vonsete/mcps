#!/usr/bin/env python3
"""
MCP server for Criminal IP — attack surface intelligence.
Free API key from https://www.criminalip.io/
Save to ~/.criminalip_key
"""

import sys
import json
import os
import urllib.request
import urllib.parse


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
    path = os.path.expanduser("~/.criminalip_key")
    if not os.path.exists(path):
        raise RuntimeError("Criminal IP API key not found. Save it to ~/.criminalip_key")
    with open(path) as f:
        return f.read().strip()

def cip_get(path, params=None):
    key = load_key()
    url = f"https://api.criminalip.io{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "x-api-key":  key,
        "User-Agent": "mcp-criminalip/1.0",
        "Accept":     "application/json",
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


TOOLS = [
    {
        "name": "cip_ip_summary",
        "description": "Quick summary for an IP: criminal score, is_vpn, is_tor, is_proxy, is_hosting, country, open ports count.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address to look up"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "cip_ip_report",
        "description": "Full IP report: criminal score, all open ports/services/banners, CVEs, geolocation, ISP, VPN/proxy/Tor detection, connected domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip":     {"type": "string",  "description": "IPv4 address"},
                "full":   {"type": "boolean", "description": "Include full details (default true)"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "cip_domain_summary",
        "description": "Quick domain summary: score, is_phishing, connected IPs, certificate info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "cip_domain_report",
        "description": "Full domain report: malicious score, linked IPs, open ports, DNS records, SSL cert, connected URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "cip_search",
        "description": "Search Criminal IP banner index. Find hosts by service/banner/product queries. Example: 'Apache port:8080 country:KR'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":  {"type": "string",  "description": "Search query (e.g. 'nginx port:443 country:ES')"},
                "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
                "limit":  {"type": "integer", "description": "Results per page (default 10, max 100)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "cip_exploit",
        "description": "Search exploits by CVE ID or product name. Returns PoC/exploit details, CVSS score, affected versions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":  {"type": "string",  "description": "CVE ID (e.g. 'CVE-2024-1234') or product name (e.g. 'Apache Log4j')"},
                "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
                "limit":  {"type": "integer", "description": "Results per page (default 10)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "cip_ip_vpn",
        "description": "Check if an IP is a VPN, proxy, Tor exit node, or hosting provider.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "cip_url_scan",
        "description": "Scan a URL for phishing, malware, and reputation. Returns threat categories and screenshot availability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to scan"},
            },
            "required": ["url"],
        },
    },
]


def _score_label(score):
    if score is None: return "unknown"
    if score >= 80:   return "critical"
    if score >= 60:   return "dangerous"
    if score >= 40:   return "moderate"
    if score >= 20:   return "low"
    return "safe"


def handle_cip_ip_summary(args):
    ip   = args["ip"]
    data = cip_get("/v1/ip/summary", {"ip": ip})
    d    = data.get("data", data)
    score = d.get("score", {})
    return {
        "ip":           ip,
        "inbound_score":  score.get("inbound"),
        "outbound_score": score.get("outbound"),
        "inbound_label":  _score_label(score.get("inbound")),
        "outbound_label": _score_label(score.get("outbound")),
        "is_vpn":       d.get("is_vpn"),
        "is_tor":       d.get("is_tor"),
        "is_proxy":     d.get("is_proxy"),
        "is_hosting":   d.get("is_hosting"),
        "is_mobile":    d.get("is_mobile"),
        "is_darkweb":   d.get("is_darkweb"),
        "country":      d.get("country"),
        "city":         d.get("city"),
        "org":          d.get("org_name") or d.get("as_name"),
        "asn":          d.get("as_no"),
        "open_ports_count": d.get("current_opened_port", {}).get("count"),
        "abuse_record_count": d.get("abuse_record_count"),
        "ids_count":    d.get("ids", {}).get("count"),
    }


def handle_cip_ip_report(args):
    ip   = args["ip"]
    full = bool(args.get("full", True))
    data = cip_get("/v1/ip/report", {"ip": ip, "full": str(full).lower()})
    d    = data.get("data", data)

    # Ports
    ports_data = d.get("port", {})
    ports = [
        {
            "port":        p.get("open_port_no"),
            "protocol":    p.get("protocol"),
            "service":     p.get("app_name"),
            "product":     p.get("product_name"),
            "version":     p.get("product_version"),
            "banner":      (p.get("banner") or "")[:150] or None,
            "is_malicious":p.get("is_malicious"),
            "socket_type": p.get("socket_type"),
        }
        for p in (ports_data.get("data") or [])[:30]
    ]

    # CVEs
    vuln_data = d.get("vulnerability", {})
    cves = [
        {
            "cve_id":   v.get("cve_id"),
            "cvss":     v.get("cvssv3_score") or v.get("cvssv2_score"),
            "severity": v.get("cvssv3_severity") or v.get("severity"),
            "product":  v.get("product_name"),
        }
        for v in (vuln_data.get("data") or [])[:20]
    ]

    score = d.get("score", {})
    return {
        "ip":             ip,
        "inbound_score":  score.get("inbound"),
        "outbound_score": score.get("outbound"),
        "inbound_label":  _score_label(score.get("inbound")),
        "country":        d.get("whois", {}).get("org_country_code") or d.get("country"),
        "city":           d.get("whois", {}).get("city"),
        "org":            d.get("whois", {}).get("org_name"),
        "asn":            d.get("whois", {}).get("as_no"),
        "is_vpn":         d.get("is_vpn"),
        "is_tor":         d.get("is_tor"),
        "is_proxy":       d.get("is_proxy"),
        "is_hosting":     d.get("is_hosting"),
        "is_scanner":     d.get("is_scanner"),
        "is_darkweb":     d.get("is_darkweb"),
        "abuse_record_count": d.get("abuse_record_count"),
        "open_ports":     ports,
        "cves":           cves,
        "cve_count":      vuln_data.get("count", len(cves)),
        "ids_alerts":     [
            {"message": i.get("message"), "classification": i.get("classification")}
            for i in (d.get("ids", {}).get("data") or [])[:10]
        ],
        "connected_domains": [
            cd.get("domain") for cd in (d.get("domain", {}).get("data") or [])[:10]
        ],
    }


def handle_cip_domain_summary(args):
    domain = args["domain"]
    data   = cip_get("/v1/domain/summary", {"domain": domain})
    d      = data.get("data", data)
    return {
        "domain":        domain,
        "score":         d.get("score"),
        "score_label":   _score_label(d.get("score")),
        "is_phishing":   d.get("is_phishing"),
        "is_malicious":  d.get("is_malicious"),
        "is_typosquatting": d.get("is_typosquatting"),
        "ip_count":      d.get("ip", {}).get("count"),
        "ips":           [i.get("ip") for i in (d.get("ip", {}).get("data") or [])[:5]],
        "ssl_valid":     (d.get("ssl") or {}).get("is_valid"),
        "ssl_expires":   ((d.get("ssl") or {}).get("not_after") or "")[:10] or None,
        "registrar":     d.get("whois", {}).get("registrar"),
        "created":       (d.get("whois", {}).get("created_date") or "")[:10] or None,
    }


def handle_cip_domain_report(args):
    domain = args["domain"]
    data   = cip_get("/v1/domain/report", {"query": domain})
    d      = data.get("data", data)

    ips = [
        {
            "ip":      i.get("ip"),
            "country": i.get("country"),
            "score":   i.get("score"),
            "is_malicious": i.get("is_malicious"),
        }
        for i in (d.get("connected_ip", {}).get("data") or [])[:15]
    ]

    return {
        "domain":       domain,
        "score":        d.get("score"),
        "score_label":  _score_label(d.get("score")),
        "is_phishing":  d.get("is_phishing"),
        "is_malicious": d.get("is_malicious"),
        "connected_ips":ips,
        "ip_count":     d.get("connected_ip", {}).get("count", len(ips)),
        "ssl": {
            "subject":   (d.get("ssl") or {}).get("subject_cn"),
            "issuer":    (d.get("ssl") or {}).get("issuer_cn"),
            "not_after": ((d.get("ssl") or {}).get("not_after") or "")[:10] or None,
            "is_valid":  (d.get("ssl") or {}).get("is_valid"),
        },
        "dns": {
            "a":    [r.get("value") for r in (d.get("dns", {}).get("a_record") or [])[:5]],
            "mx":   [r.get("value") for r in (d.get("dns", {}).get("mx_record") or [])[:5]],
            "ns":   [r.get("value") for r in (d.get("dns", {}).get("ns_record") or [])[:5]],
        },
        "whois": {
            "registrar": d.get("whois", {}).get("registrar"),
            "created":   (d.get("whois", {}).get("created_date") or "")[:10] or None,
            "expires":   (d.get("whois", {}).get("expiry_date") or "")[:10] or None,
            "org":       d.get("whois", {}).get("org_name"),
        },
        "ports": [
            {"port": p.get("port"), "service": p.get("app_name"), "product": p.get("product_name")}
            for p in (d.get("port", {}).get("data") or [])[:15]
        ],
    }


def handle_cip_search(args):
    limit  = min(int(args.get("limit", 10)), 100)
    offset = int(args.get("offset", 0))
    data   = cip_get("/v1/banner/search", {
        "query":  args["query"],
        "offset": offset,
        "limit":  limit,
    })
    d = data.get("data", data)
    results = d.get("result", d.get("data", []))
    return {
        "query":  args["query"],
        "count":  len(results),
        "total":  d.get("count") or d.get("total"),
        "results": [
            {
                "ip":       r.get("ip_address") or r.get("ip"),
                "port":     r.get("open_port_no") or r.get("port"),
                "protocol": r.get("protocol"),
                "service":  r.get("app_name") or r.get("service"),
                "banner":   (r.get("banner") or "")[:200] or None,
                "country":  r.get("country_code") or r.get("country"),
                "score":    r.get("score", {}).get("inbound") if isinstance(r.get("score"), dict) else r.get("score"),
                "is_vpn":   r.get("is_vpn"),
                "is_tor":   r.get("is_tor"),
            }
            for r in results[:limit]
        ],
    }


def handle_cip_exploit(args):
    limit  = min(int(args.get("limit", 10)), 100)
    offset = int(args.get("offset", 0))
    data   = cip_get("/v1/exploit/search", {
        "query":  args["query"],
        "offset": offset,
        "limit":  limit,
    })
    d       = data.get("data", data)
    results = d.get("result", d.get("data", []))
    return {
        "query":  args["query"],
        "count":  len(results),
        "total":  d.get("count") or d.get("total"),
        "exploits": [
            {
                "cve_id":       e.get("cve_id"),
                "cvss_score":   e.get("cvssv3_score") or e.get("cvssv2_score"),
                "severity":     e.get("cvssv3_severity") or e.get("severity"),
                "title":        e.get("vuln_title") or e.get("title"),
                "description":  (e.get("description") or "")[:300] or None,
                "affected":     e.get("product_name"),
                "exploit_type": e.get("exploit_type") or e.get("type"),
                "published":    (e.get("published_date") or "")[:10] or None,
                "references":   (e.get("references") or [])[:3],
            }
            for e in results[:limit]
        ],
    }


def handle_cip_ip_vpn(args):
    ip   = args["ip"]
    data = cip_get("/v1/feature/ip/vpn", {"ip": ip})
    d    = data.get("data", data)
    return {
        "ip":         ip,
        "is_vpn":     d.get("is_vpn"),
        "is_tor":     d.get("is_tor"),
        "is_proxy":   d.get("is_proxy"),
        "is_hosting": d.get("is_hosting"),
        "is_mobile":  d.get("is_mobile"),
        "is_darkweb": d.get("is_darkweb"),
        "is_scanner": d.get("is_scanner"),
        "vpn_name":   d.get("vpn_name"),
        "confirmed":  d.get("confirmed"),
    }


def handle_cip_url_scan(args):
    url  = args["url"]
    data = cip_get("/v1/url/report", {"query": url})
    d    = data.get("data", data)
    return {
        "url":          url,
        "score":        d.get("score"),
        "is_phishing":  d.get("is_phishing"),
        "is_malicious": d.get("is_malicious"),
        "categories":   d.get("categories", []),
        "ip":           d.get("ip"),
        "country":      d.get("country"),
        "status_code":  d.get("status_code"),
        "title":        d.get("title"),
        "final_url":    d.get("final_url"),
        "scan_time":    (d.get("scan_time") or "")[:19] or None,
    }


HANDLERS = {
    "cip_ip_summary":    handle_cip_ip_summary,
    "cip_ip_report":     handle_cip_ip_report,
    "cip_domain_summary":handle_cip_domain_summary,
    "cip_domain_report": handle_cip_domain_report,
    "cip_search":        handle_cip_search,
    "cip_exploit":       handle_cip_exploit,
    "cip_ip_vpn":        handle_cip_ip_vpn,
    "cip_url_scan":      handle_cip_url_scan,
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
                "serverInfo": {"name": "criminalip-mcp", "version": "1.0.0"},
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
