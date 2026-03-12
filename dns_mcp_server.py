#!/usr/bin/env python3
"""
MCP server for DNS lookups.
No API key required — uses dnspython.
"""

import sys
import json
import dns.resolver
import dns.reversename
import dns.rdatatype


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

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "dns_lookup",
        "description": "Resolve a domain for a given record type (A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, CAA, PTR).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":      {"type": "string", "description": "Domain to query (e.g. 'google.com')"},
                "record_type": {"type": "string", "description": "DNS record type (default: A)"},
                "nameserver":  {"type": "string", "description": "Optional custom nameserver to use (e.g. '8.8.8.8')"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "dns_reverse_lookup",
        "description": "Reverse DNS lookup — resolve an IP address to its hostname(s).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address (e.g. '8.8.8.8')"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "dns_check_spf",
        "description": "Retrieve and analyse the SPF record for a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check SPF for"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "dns_check_dmarc",
        "description": "Retrieve and analyse the DMARC record for a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check DMARC for"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "dns_check_dkim",
        "description": "Retrieve the DKIM public key record for a domain and selector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":   {"type": "string", "description": "Domain (e.g. 'google.com')"},
                "selector": {"type": "string", "description": "DKIM selector (e.g. 'google', 'default', 'mail')"},
            },
            "required": ["domain", "selector"],
        },
    },
    {
        "name": "dns_full_audit",
        "description": "Full DNS audit of a domain: A, AAAA, MX, NS, TXT, SPF, DMARC, CAA records.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to audit"},
            },
            "required": ["domain"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def resolve(domain, rtype="A", nameserver=None):
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    try:
        answers = resolver.resolve(domain, rtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except Exception as e:
        return [f"error: {e}"]


def handle_dns_lookup(args):
    domain     = args.get("domain")
    rtype      = args.get("record_type", "A").upper()
    nameserver = args.get("nameserver")
    records    = resolve(domain, rtype, nameserver)
    return {"domain": domain, "type": rtype, "records": records, "count": len(records)}


def handle_dns_reverse_lookup(args):
    ip = args.get("ip")
    try:
        rev_name = dns.reversename.from_address(ip)
        records  = resolve(str(rev_name), "PTR")
        return {"ip": ip, "hostnames": records}
    except Exception as e:
        return {"ip": ip, "hostnames": [], "error": str(e)}


def handle_dns_check_spf(args):
    domain = args.get("domain")
    txt_records = resolve(domain, "TXT")
    spf = [r.strip('"') for r in txt_records if "v=spf1" in r]
    if not spf:
        return {"domain": domain, "spf_found": False, "record": None}
    record = spf[0]
    mechanisms = record.split()
    return {
        "domain":     domain,
        "spf_found":  True,
        "record":     record,
        "mechanisms": mechanisms,
        "all_policy": next((m for m in mechanisms if m.startswith("~all") or m.startswith("-all") or m.startswith("+all") or m == "all"), None),
    }


def handle_dns_check_dmarc(args):
    domain = args.get("domain")
    dmarc_domain = f"_dmarc.{domain}"
    txt_records  = resolve(dmarc_domain, "TXT")
    dmarc = [r.strip('"') for r in txt_records if "v=DMARC1" in r]
    if not dmarc:
        return {"domain": domain, "dmarc_found": False, "record": None}
    record = dmarc[0]
    tags   = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = v.strip()
    return {
        "domain":      domain,
        "dmarc_found": True,
        "record":      record,
        "policy":      tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "rua":         tags.get("rua"),
        "ruf":         tags.get("ruf"),
        "pct":         tags.get("pct"),
        "tags":        tags,
    }


def handle_dns_check_dkim(args):
    domain   = args.get("domain")
    selector = args.get("selector")
    dkim_domain = f"{selector}._domainkey.{domain}"
    txt_records = resolve(dkim_domain, "TXT")
    if not txt_records:
        return {"domain": domain, "selector": selector, "dkim_found": False, "record": None}
    record = " ".join(r.strip('"') for r in txt_records)
    tags   = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = v.strip()
    return {
        "domain":     domain,
        "selector":   selector,
        "dkim_found": True,
        "record":     record,
        "key_type":   tags.get("k", "rsa"),
        "hash_algs":  tags.get("h"),
        "public_key": tags.get("p", "")[:60] + "..." if len(tags.get("p", "")) > 60 else tags.get("p"),
    }


def handle_dns_full_audit(args):
    domain = args.get("domain")
    result = {"domain": domain}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
        result[rtype] = resolve(domain, rtype)
    # CNAME
    result["CNAME"] = resolve(domain, "CNAME")
    # SPF from TXT
    spf = [r.strip('"') for r in result["TXT"] if "v=spf1" in r]
    result["SPF"] = spf[0] if spf else None
    # DMARC
    dmarc_txt = resolve(f"_dmarc.{domain}", "TXT")
    dmarc = [r.strip('"') for r in dmarc_txt if "v=DMARC1" in r]
    result["DMARC"] = dmarc[0] if dmarc else None
    return result


HANDLERS = {
    "dns_lookup":          handle_dns_lookup,
    "dns_reverse_lookup":  handle_dns_reverse_lookup,
    "dns_check_spf":       handle_dns_check_spf,
    "dns_check_dmarc":     handle_dns_check_dmarc,
    "dns_check_dkim":      handle_dns_check_dkim,
    "dns_full_audit":      handle_dns_full_audit,
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
                "serverInfo": {"name": "dns-mcp", "version": "1.0.0"},
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
