#!/usr/bin/env python3
"""
MCP server for MikroTik RouterOS — uses the native MikroTik API (port 8728/8729).
Compatible with RouterOS 6.x and 7.x.

Enable API on MikroTik:
  /ip service set api disabled=no port=8728
  /ip service set api-ssl disabled=no port=8729  (optional, for SSL)

Credentials read from ~/.mikrotik_key (JSON):
  {"host": "192.168.1.1", "user": "admin", "password": "secret", "port": 8728}

Or passed as parameters per call.
"""

import sys
import json
import os
from librouteros import connect
from librouteros.query import Key


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

def load_defaults():
    path = os.path.expanduser("~/.mikrotik_key")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def mk(args):
    d        = load_defaults()
    host     = args.get("host")     or d.get("host")
    user     = args.get("user")     or d.get("user", "admin")
    password = args.get("password") or d.get("password", "")
    port     = int(args.get("port", d.get("port", 8728)))
    if not host:
        raise RuntimeError("Missing host. Pass it as parameter or save to ~/.mikrotik_key")
    return connect(username=user, password=password, host=host, port=port, timeout=10)

def query(api, path, **filters):
    """Execute a MikroTik API query and return list of dicts."""
    resource = api.path(*path.strip("/").split("/"))
    if filters:
        conditions = [Key(k) == v for k, v in filters.items()]
        rows = list(resource.select(*[]).where(*conditions))
    else:
        rows = list(resource)
    # Convert to plain dicts, clean up keys
    result = []
    for row in rows:
        d = {}
        for k, v in row.items():
            clean_key = k.lstrip("=").lstrip(".")
            d[clean_key] = v
        result.append(d)
    return result

def add(api, path, **kwargs):
    resource = api.path(*path.strip("/").split("/"))
    return resource.add(**kwargs)

def update(api, path, id, **kwargs):
    resource = api.path(*path.strip("/").split("/"))
    resource.update(**{"=.id": id, **kwargs})

def remove(api, path, id):
    resource = api.path(*path.strip("/").split("/"))
    resource.remove(id)


# ---------------------------------------------------------------------------
# Connection params
# ---------------------------------------------------------------------------

CONN_PROPS = {
    "host":     {"type": "string",  "description": "MikroTik IP or hostname"},
    "user":     {"type": "string",  "description": "Username (default 'admin')"},
    "password": {"type": "string",  "description": "Password"},
    "port":     {"type": "integer", "description": "API port (default 8728, SSL: 8729)"},
}

def schema(extra=None, required=None):
    props = dict(CONN_PROPS)
    if extra:
        props.update(extra)
    return {"type": "object", "properties": props, "required": required or []}


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------

TOOLS = [
    # System
    {
        "name": "mt_system_info",
        "description": "Get system info: hostname, model, RouterOS version, CPU, memory, uptime.",
        "inputSchema": schema(),
    },
    {
        "name": "mt_system_resources",
        "description": "Get resource usage: CPU load, free/total memory, disk, uptime.",
        "inputSchema": schema(),
    },
    {
        "name": "mt_get_log",
        "description": "Get system log entries, optionally filtered by topic (firewall, dhcp, system, etc.).",
        "inputSchema": schema({
            "topics": {"type": "string",  "description": "Filter by topic (e.g. 'firewall', 'dhcp')"},
            "limit":  {"type": "integer", "description": "Number of entries (default 50)"},
        }),
    },
    # Interfaces
    {
        "name": "mt_list_interfaces",
        "description": "List all network interfaces with status, MAC, TX/RX stats.",
        "inputSchema": schema(),
    },
    {
        "name": "mt_list_ip_addresses",
        "description": "List all IP addresses assigned to interfaces.",
        "inputSchema": schema(),
    },
    # Firewall
    {
        "name": "mt_fw_filter_rules",
        "description": "List firewall filter rules (input, output, forward chains).",
        "inputSchema": schema({
            "chain": {"type": "string", "description": "Filter by chain: input, output, forward"},
        }),
    },
    {
        "name": "mt_fw_nat_rules",
        "description": "List NAT rules (srcnat/masquerade, dstnat/port forwarding).",
        "inputSchema": schema({
            "chain": {"type": "string", "description": "Filter by chain: srcnat, dstnat"},
        }),
    },
    {
        "name": "mt_fw_mangle_rules",
        "description": "List mangle rules (marking, QoS).",
        "inputSchema": schema(),
    },
    {
        "name": "mt_fw_address_lists",
        "description": "List firewall address lists (IP blacklists/whitelists).",
        "inputSchema": schema({
            "list": {"type": "string", "description": "Filter by list name"},
        }),
    },
    {
        "name": "mt_fw_add_filter_rule",
        "description": "Add a firewall filter rule.",
        "inputSchema": schema({
            "chain":         {"type": "string",  "description": "input | output | forward"},
            "action":        {"type": "string",  "description": "accept | drop | reject | log"},
            "src_address":   {"type": "string",  "description": "Source IP/CIDR (optional)"},
            "dst_address":   {"type": "string",  "description": "Destination IP/CIDR (optional)"},
            "protocol":      {"type": "string",  "description": "tcp | udp | icmp (optional)"},
            "dst_port":      {"type": "string",  "description": "Destination port(s) e.g. '80,443'"},
            "in_interface":  {"type": "string",  "description": "Incoming interface (optional)"},
            "out_interface": {"type": "string",  "description": "Outgoing interface (optional)"},
            "comment":       {"type": "string",  "description": "Rule comment"},
            "disabled":      {"type": "boolean", "description": "Create as disabled"},
            "place_before":  {"type": "string",  "description": "Place before rule with this ID"},
        }, required=["chain", "action"]),
    },
    {
        "name": "mt_fw_add_address_to_list",
        "description": "Add an IP address to a firewall address list.",
        "inputSchema": schema({
            "list":    {"type": "string", "description": "Address list name"},
            "address": {"type": "string", "description": "IP address or CIDR"},
            "comment": {"type": "string", "description": "Comment (optional)"},
            "timeout": {"type": "string", "description": "Auto-remove timeout e.g. '1d', '2h30m'"},
        }, required=["list", "address"]),
    },
    {
        "name": "mt_fw_toggle_rule",
        "description": "Enable or disable a firewall filter rule by ID.",
        "inputSchema": schema({
            "rule_id":  {"type": "string",  "description": "Rule .id value"},
            "disabled": {"type": "boolean", "description": "true to disable, false to enable"},
        }, required=["rule_id", "disabled"]),
    },
    {
        "name": "mt_fw_delete_rule",
        "description": "Delete a firewall filter rule by ID.",
        "inputSchema": schema({
            "rule_id": {"type": "string", "description": "Rule .id value"},
        }, required=["rule_id"]),
    },
    {
        "name": "mt_fw_connections",
        "description": "List active tracked connections/sessions.",
        "inputSchema": schema({
            "limit": {"type": "integer", "description": "Number of connections (default 50)"},
        }),
    },
    # Routing & ARP
    {
        "name": "mt_ip_routes",
        "description": "List IP routing table.",
        "inputSchema": schema(),
    },
    {
        "name": "mt_arp_table",
        "description": "List ARP table (IP to MAC mappings).",
        "inputSchema": schema(),
    },
    {
        "name": "mt_neighbors",
        "description": "List discovered neighbors (MNDP/LLDP/CDP).",
        "inputSchema": schema(),
    },
    # DHCP
    {
        "name": "mt_dhcp_leases",
        "description": "List DHCP leases (active and static).",
        "inputSchema": schema({
            "server": {"type": "string", "description": "Filter by DHCP server name"},
        }),
    },
    {
        "name": "mt_dhcp_servers",
        "description": "List DHCP server configurations.",
        "inputSchema": schema(),
    },
    # Users & Queues
    {
        "name": "mt_list_users",
        "description": "List system users and their groups/permissions.",
        "inputSchema": schema(),
    },
    {
        "name": "mt_simple_queues",
        "description": "List simple queues (bandwidth limits per IP/subnet).",
        "inputSchema": schema(),
    },
    # DNS
    {
        "name": "mt_dns_config",
        "description": "Get DNS configuration and static DNS entries.",
        "inputSchema": schema(),
    },
    # Wireless
    {
        "name": "mt_wireless_clients",
        "description": "List connected wireless clients (requires wireless package).",
        "inputSchema": schema(),
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_mt_system_info(args):
    api      = mk(args)
    identity = query(api, "/system/identity")
    resource = query(api, "/system/resource")
    res      = resource[0] if resource else {}
    ident    = identity[0] if identity else {}
    return {
        "name":         ident.get("name"),
        "model":        res.get("board-name"),
        "version":      res.get("version"),
        "cpu":          res.get("cpu"),
        "cpu_count":    res.get("cpu-count"),
        "architecture": res.get("architecture-name"),
        "uptime":       res.get("uptime"),
    }


def handle_mt_system_resources(args):
    api  = mk(args)
    rows = query(api, "/system/resource")
    res  = rows[0] if rows else {}
    try:
        free_mem   = int(res.get("free-memory",  0))
        total_mem  = int(res.get("total-memory", 1))
        free_disk  = int(res.get("free-hdd-space",  0))
        total_disk = int(res.get("total-hdd-space", 1))
        res["mem_used_pct"]  = round((total_mem - free_mem) / total_mem * 100, 1)
        res["mem_total_mb"]  = round(total_mem / 1024 / 1024, 1)
        res["mem_free_mb"]   = round(free_mem  / 1024 / 1024, 1)
        res["disk_used_pct"] = round((total_disk - free_disk) / total_disk * 100, 1)
        res["disk_total_mb"] = round(total_disk / 1024 / 1024, 1)
        res["disk_free_mb"]  = round(free_disk  / 1024 / 1024, 1)
    except Exception:
        pass
    return res


def handle_mt_get_log(args):
    api    = mk(args)
    limit  = int(args.get("limit", 50))
    topic  = args.get("topics", "")
    rows   = query(api, "/log")
    if topic:
        rows = [r for r in rows if topic.lower() in str(r.get("topics", "")).lower()]
    return {"total": len(rows), "entries": rows[-limit:]}


def handle_mt_list_interfaces(args):
    api   = mk(args)
    ifaces = query(api, "/interface")
    return {
        "total": len(ifaces),
        "interfaces": [
            {
                "name":     i.get("name"),
                "type":     i.get("type"),
                "mac":      i.get("mac-address"),
                "mtu":      i.get("mtu"),
                "running":  i.get("running"),
                "disabled": i.get("disabled"),
                "rx_bytes": i.get("rx-byte"),
                "tx_bytes": i.get("tx-byte"),
                "rx_errors":i.get("rx-error"),
                "tx_errors":i.get("tx-error"),
                "comment":  i.get("comment"),
            }
            for i in ifaces
        ],
    }


def handle_mt_list_ip_addresses(args):
    api  = mk(args)
    rows = query(api, "/ip/address")
    return {
        "total": len(rows),
        "addresses": [
            {
                "id":        r.get("id"),
                "address":   r.get("address"),
                "network":   r.get("network"),
                "interface": r.get("interface"),
                "disabled":  r.get("disabled"),
                "comment":   r.get("comment"),
            }
            for r in rows
        ],
    }


def _parse_fw(r):
    return {
        "id":            r.get("id"),
        "chain":         r.get("chain"),
        "action":        r.get("action"),
        "src_address":   r.get("src-address"),
        "dst_address":   r.get("dst-address"),
        "protocol":      r.get("protocol"),
        "src_port":      r.get("src-port"),
        "dst_port":      r.get("dst-port"),
        "in_interface":  r.get("in-interface"),
        "out_interface": r.get("out-interface"),
        "connection_state": r.get("connection-state"),
        "disabled":      r.get("disabled"),
        "comment":       r.get("comment"),
        "bytes":         r.get("bytes"),
        "packets":       r.get("packets"),
        "log":           r.get("log"),
        "log_prefix":    r.get("log-prefix"),
    }


def handle_mt_fw_filter_rules(args):
    api   = mk(args)
    rules = query(api, "/ip/firewall/filter")
    chain = args.get("chain", "").lower()
    if chain:
        rules = [r for r in rules if r.get("chain", "").lower() == chain]
    return {"total": len(rules), "rules": [_parse_fw(r) for r in rules]}


def handle_mt_fw_nat_rules(args):
    api   = mk(args)
    rules = query(api, "/ip/firewall/nat")
    chain = args.get("chain", "").lower()
    if chain:
        rules = [r for r in rules if r.get("chain", "").lower() == chain]
    return {
        "total": len(rules),
        "rules": [
            {
                "id":           r.get("id"),
                "chain":        r.get("chain"),
                "action":       r.get("action"),
                "src_address":  r.get("src-address"),
                "dst_address":  r.get("dst-address"),
                "protocol":     r.get("protocol"),
                "dst_port":     r.get("dst-port"),
                "to_addresses": r.get("to-addresses"),
                "to_ports":     r.get("to-ports"),
                "out_interface":r.get("out-interface"),
                "disabled":     r.get("disabled"),
                "comment":      r.get("comment"),
                "bytes":        r.get("bytes"),
            }
            for r in rules
        ],
    }


def handle_mt_fw_mangle_rules(args):
    api   = mk(args)
    rules = query(api, "/ip/firewall/mangle")
    return {"total": len(rules), "rules": [_parse_fw(r) for r in rules]}


def handle_mt_fw_address_lists(args):
    api     = mk(args)
    entries = query(api, "/ip/firewall/address-list")
    lst     = args.get("list", "").lower()
    if lst:
        entries = [e for e in entries if e.get("list", "").lower() == lst]
    return {
        "total": len(entries),
        "entries": [
            {
                "id":      e.get("id"),
                "list":    e.get("list"),
                "address": e.get("address"),
                "disabled":e.get("disabled"),
                "comment": e.get("comment"),
                "timeout": e.get("timeout"),
                "dynamic": e.get("dynamic"),
            }
            for e in entries
        ],
    }


def handle_mt_fw_add_filter_rule(args):
    api  = mk(args)
    body = {"chain": args["chain"], "action": args["action"]}
    for field, key in [
        ("src_address", "src-address"), ("dst_address", "dst-address"),
        ("protocol", "protocol"), ("dst_port", "dst-port"), ("src_port", "src-port"),
        ("in_interface", "in-interface"), ("out_interface", "out-interface"),
        ("comment", "comment"), ("place_before", "place-before"),
    ]:
        if args.get(field):
            body[key] = args[field]
    if args.get("disabled"):
        body["disabled"] = "yes"
    resource = api.path("ip", "firewall", "filter")
    result   = resource.add(**body)
    return {"created": True, "id": str(result)}


def handle_mt_fw_add_address_to_list(args):
    api  = mk(args)
    body = {"list": args["list"], "address": args["address"]}
    if args.get("comment"):
        body["comment"] = args["comment"]
    if args.get("timeout"):
        body["timeout"] = args["timeout"]
    resource = api.path("ip", "firewall", "address-list")
    result   = resource.add(**body)
    return {"created": True, "id": str(result)}


def handle_mt_fw_toggle_rule(args):
    api      = mk(args)
    rule_id  = args["rule_id"]
    disabled = "yes" if args["disabled"] else "no"
    resource = api.path("ip", "firewall", "filter")
    resource.update(**{"=.id": rule_id, "=disabled": disabled})
    return {"updated": True, "rule_id": rule_id, "disabled": args["disabled"]}


def handle_mt_fw_delete_rule(args):
    api      = mk(args)
    rule_id  = args["rule_id"]
    resource = api.path("ip", "firewall", "filter")
    resource.remove(rule_id)
    return {"deleted": True, "rule_id": rule_id}


def handle_mt_fw_connections(args):
    api   = mk(args)
    limit = int(args.get("limit", 50))
    conns = query(api, "/ip/firewall/connection")
    return {
        "total": len(conns),
        "connections": [
            {
                "protocol":    c.get("protocol"),
                "src_address": c.get("src-address"),
                "dst_address": c.get("dst-address"),
                "state":       c.get("tcp-state"),
                "timeout":     c.get("timeout"),
                "orig_bytes":  c.get("orig-bytes"),
                "repl_bytes":  c.get("repl-bytes"),
            }
            for c in conns[:limit]
        ],
    }


def handle_mt_ip_routes(args):
    api    = mk(args)
    routes = query(api, "/ip/route")
    return {
        "total": len(routes),
        "routes": [
            {
                "id":        r.get("id"),
                "dst":       r.get("dst-address"),
                "gateway":   r.get("gateway"),
                "interface": r.get("interface"),
                "distance":  r.get("distance"),
                "active":    r.get("active"),
                "dynamic":   r.get("dynamic"),
                "comment":   r.get("comment"),
            }
            for r in routes
        ],
    }


def handle_mt_arp_table(args):
    api  = mk(args)
    arps = query(api, "/ip/arp")
    return {
        "total": len(arps),
        "arp": [
            {
                "address":   a.get("address"),
                "mac":       a.get("mac-address"),
                "interface": a.get("interface"),
                "dynamic":   a.get("dynamic"),
                "complete":  a.get("complete"),
                "comment":   a.get("comment"),
            }
            for a in arps
        ],
    }


def handle_mt_neighbors(args):
    api   = mk(args)
    neigh = query(api, "/ip/neighbor")
    return {
        "total": len(neigh),
        "neighbors": [
            {
                "interface": n.get("interface"),
                "address":   n.get("address"),
                "mac":       n.get("mac-address"),
                "identity":  n.get("identity"),
                "platform":  n.get("platform"),
                "version":   n.get("version"),
                "board":     n.get("board"),
                "uptime":    n.get("uptime"),
            }
            for n in neigh
        ],
    }


def handle_mt_dhcp_leases(args):
    api    = mk(args)
    leases = query(api, "/ip/dhcp-server/lease")
    server = args.get("server", "").lower()
    if server:
        leases = [l for l in leases if l.get("server", "").lower() == server]
    return {
        "total": len(leases),
        "leases": [
            {
                "address":  l.get("address"),
                "mac":      l.get("mac-address"),
                "hostname": l.get("host-name"),
                "server":   l.get("server"),
                "status":   l.get("status"),
                "expires":  l.get("expires-after"),
                "dynamic":  l.get("dynamic"),
                "blocked":  l.get("blocked"),
                "comment":  l.get("comment"),
            }
            for l in leases
        ],
    }


def handle_mt_dhcp_servers(args):
    api     = mk(args)
    servers = query(api, "/ip/dhcp-server")
    return {"total": len(servers), "servers": servers}


def handle_mt_list_users(args):
    api   = mk(args)
    users = query(api, "/user")
    return {
        "total": len(users),
        "users": [
            {
                "name":     u.get("name"),
                "group":    u.get("group"),
                "address":  u.get("address"),
                "disabled": u.get("disabled"),
                "comment":  u.get("comment"),
                "last_logged_in": u.get("last-logged-in"),
            }
            for u in users
        ],
    }


def handle_mt_simple_queues(args):
    api    = mk(args)
    queues = query(api, "/queue/simple")
    return {
        "total": len(queues),
        "queues": [
            {
                "name":       q.get("name"),
                "target":     q.get("target"),
                "max_limit":  q.get("max-limit"),
                "burst_limit":q.get("burst-limit"),
                "disabled":   q.get("disabled"),
                "bytes":      q.get("bytes"),
                "comment":    q.get("comment"),
            }
            for q in queues
        ],
    }


def handle_mt_dns_config(args):
    api     = mk(args)
    config  = query(api, "/ip/dns")
    statics = query(api, "/ip/dns/static")
    cfg     = config[0] if config else {}
    return {
        "servers":        cfg.get("servers"),
        "allow_remote":   cfg.get("allow-remote-requests"),
        "cache_size_kb":  cfg.get("cache-size"),
        "cache_used_kb":  cfg.get("cache-used"),
        "static_entries": [
            {"name": s.get("name"), "address": s.get("address"),
             "type": s.get("type"), "disabled": s.get("disabled")}
            for s in statics
        ],
    }


def handle_mt_wireless_clients(args):
    api = mk(args)
    try:
        clients = query(api, "/interface/wireless/registration-table")
        return {
            "total": len(clients),
            "clients": [
                {
                    "mac":       c.get("mac-address"),
                    "interface": c.get("interface"),
                    "signal":    c.get("signal-strength"),
                    "tx_rate":   c.get("tx-rate"),
                    "rx_rate":   c.get("rx-rate"),
                    "uptime":    c.get("uptime"),
                    "tx_bytes":  c.get("tx-bytes"),
                    "rx_bytes":  c.get("rx-bytes"),
                }
                for c in clients
            ],
        }
    except Exception as e:
        return {"error": str(e), "note": "Requires wireless package installed"}


HANDLERS = {
    "mt_system_info":            handle_mt_system_info,
    "mt_system_resources":       handle_mt_system_resources,
    "mt_get_log":                handle_mt_get_log,
    "mt_list_interfaces":        handle_mt_list_interfaces,
    "mt_list_ip_addresses":      handle_mt_list_ip_addresses,
    "mt_fw_filter_rules":        handle_mt_fw_filter_rules,
    "mt_fw_nat_rules":           handle_mt_fw_nat_rules,
    "mt_fw_mangle_rules":        handle_mt_fw_mangle_rules,
    "mt_fw_address_lists":       handle_mt_fw_address_lists,
    "mt_fw_add_filter_rule":     handle_mt_fw_add_filter_rule,
    "mt_fw_add_address_to_list": handle_mt_fw_add_address_to_list,
    "mt_fw_toggle_rule":         handle_mt_fw_toggle_rule,
    "mt_fw_delete_rule":         handle_mt_fw_delete_rule,
    "mt_fw_connections":         handle_mt_fw_connections,
    "mt_ip_routes":              handle_mt_ip_routes,
    "mt_arp_table":              handle_mt_arp_table,
    "mt_neighbors":              handle_mt_neighbors,
    "mt_dhcp_leases":            handle_mt_dhcp_leases,
    "mt_dhcp_servers":           handle_mt_dhcp_servers,
    "mt_list_users":             handle_mt_list_users,
    "mt_simple_queues":          handle_mt_simple_queues,
    "mt_dns_config":             handle_mt_dns_config,
    "mt_wireless_clients":       handle_mt_wireless_clients,
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
                "serverInfo": {"name": "mikrotik-mcp", "version": "1.0.0"},
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
