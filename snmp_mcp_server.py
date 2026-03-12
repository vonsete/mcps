#!/usr/bin/env python3
"""
MCP server for SNMP v1/v2c — pure Python, no external dependencies.
Uses raw UDP sockets with BER/ASN.1 encoding.

Supports: GET, GETNEXT (walk), GETBULK
"""

import sys
import json
import socket
import struct
import random
import time


# ---------------------------------------------------------------------------
# BER / ASN.1 encoder/decoder (minimal, enough for SNMP v1/v2c)
# ---------------------------------------------------------------------------

# ASN.1 tags
TAG_INT        = 0x02
TAG_OCTETSTR   = 0x04
TAG_NULL       = 0x05
TAG_OID        = 0x06
TAG_SEQUENCE   = 0x30
TAG_IPADDR     = 0x40
TAG_COUNTER32  = 0x41
TAG_GAUGE32    = 0x42
TAG_TIMETICKS  = 0x43
TAG_COUNTER64  = 0x46
TAG_NOSUCHOBJ  = 0x80
TAG_NOSUCHINST = 0x81
TAG_ENDOFMIB   = 0x82
TAG_GETREQ     = 0xA0
TAG_GETNEXT    = 0xA1
TAG_RESPONSE   = 0xA2
TAG_GETBULK    = 0xA5


def encode_length(n):
    if n < 0x80:
        return bytes([n])
    enc = []
    while n:
        enc.append(n & 0xFF)
        n >>= 8
    enc.reverse()
    return bytes([0x80 | len(enc)] + enc)


def encode_tlv(tag, value):
    return bytes([tag]) + encode_length(len(value)) + value


def encode_int(n):
    if n == 0:
        return encode_tlv(TAG_INT, b'\x00')
    neg  = n < 0
    enc  = []
    num  = n if n > 0 else -n - 1
    while num:
        enc.append(num & 0xFF if not neg else (~num) & 0xFF)
        num >>= 8
    if not enc:
        enc = [0xFF if neg else 0x00]
    enc.reverse()
    # Sign extension
    msb = enc[0]
    if neg and msb < 0x80:
        enc = [0xFF] + enc
    if not neg and msb >= 0x80:
        enc = [0x00] + enc
    return encode_tlv(TAG_INT, bytes(enc))


def encode_octetstr(s):
    if isinstance(s, str):
        s = s.encode()
    return encode_tlv(TAG_OCTETSTR, s)


def encode_null():
    return encode_tlv(TAG_NULL, b'')


def encode_oid(oid_str):
    parts = [int(x) for x in oid_str.strip('.').split('.')]
    if len(parts) < 2:
        parts = [1, 3] + parts
    enc = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            enc.append(0)
        else:
            sub = []
            while part:
                sub.append(part & 0x7F)
                part >>= 7
            sub.reverse()
            for i, b in enumerate(sub):
                enc.append(b | (0x80 if i < len(sub) - 1 else 0))
    return encode_tlv(TAG_OID, bytes(enc))


def encode_sequence(items):
    body = b''.join(items)
    return encode_tlv(TAG_SEQUENCE, body)


def encode_pdu(pdu_tag, req_id, error_status, error_index, var_binds):
    vb_list = b''.join(
        encode_sequence([encode_oid(oid), encode_null()])
        for oid in var_binds
    )
    body = (encode_int(req_id) + encode_int(error_status) +
            encode_int(error_index) + encode_tlv(TAG_SEQUENCE, vb_list))
    return encode_tlv(pdu_tag, body)


def build_packet(community, pdu_tag, req_id, var_binds,
                 version=1, non_repeaters=0, max_repetitions=10):
    if pdu_tag == TAG_GETBULK:
        vb_list = b''.join(
            encode_sequence([encode_oid(oid), encode_null()])
            for oid in var_binds
        )
        body = (encode_int(non_repeaters) + encode_int(max_repetitions) +
                encode_tlv(TAG_SEQUENCE, vb_list))
        pdu = encode_tlv(TAG_GETBULK, body)
    else:
        pdu = encode_pdu(pdu_tag, req_id, 0, 0, var_binds)

    msg = encode_sequence([
        encode_int(version),
        encode_octetstr(community),
        pdu,
    ])
    return msg


# ---------------------------------------------------------------------------
# BER decoder
# ---------------------------------------------------------------------------

def decode_length(data, pos):
    b = data[pos]; pos += 1
    if b < 0x80:
        return b, pos
    num_bytes = b & 0x7F
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[pos]; pos += 1
    return length, pos


def decode_tlv(data, pos):
    tag    = data[pos]; pos += 1
    length, pos = decode_length(data, pos)
    value  = data[pos:pos + length]
    return tag, value, pos + length


def decode_int(value):
    if not value:
        return 0
    n = value[0]
    neg = n >= 0x80
    if neg:
        n -= 0x100
    for b in value[1:]:
        n = (n << 8) | b
    return n


def decode_oid(value):
    if not value:
        return "0.0"
    first = value[0]
    parts = [first // 40, first % 40]
    i, cur = 1, 0
    while i < len(value):
        b = value[i]; i += 1
        cur = (cur << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(cur)
            cur = 0
    return '.' + '.'.join(str(p) for p in parts)


def decode_value(tag, raw):
    if tag == TAG_INT:
        return decode_int(raw)
    if tag == TAG_OCTETSTR:
        try:
            s = raw.decode('utf-8')
            if s.isprintable() or ' ' in s:
                return s
        except Exception:
            pass
        return raw.hex(':')
    if tag == TAG_OID:
        return decode_oid(raw)
    if tag == TAG_NULL:
        return None
    if tag == TAG_IPADDR and len(raw) == 4:
        return '.'.join(str(b) for b in raw)
    if tag in (TAG_COUNTER32, TAG_GAUGE32):
        n = 0
        for b in raw:
            n = (n << 8) | b
        return n
    if tag == TAG_TIMETICKS:
        ticks = 0
        for b in raw:
            ticks = (ticks << 8) | b
        s = ticks // 100
        d = s // 86400; s %= 86400
        h = s // 3600;  s %= 3600
        m = s // 60;    s %= 60
        return f"{d}d {h:02d}:{m:02d}:{s:02d}"
    if tag == TAG_COUNTER64:
        n = 0
        for b in raw:
            n = (n << 8) | b
        return n
    if tag in (TAG_NOSUCHOBJ, TAG_NOSUCHINST, TAG_ENDOFMIB):
        return None
    return raw.hex()


def decode_varbinds(data, pos, end):
    """Decode VarBindList from position pos to end."""
    results = []
    while pos < end:
        tag, seq_val, pos = decode_tlv(data, pos)
        if tag != TAG_SEQUENCE:
            continue
        p2 = 0
        oid_tag, oid_raw, p2 = decode_tlv(seq_val, p2)
        val_tag, val_raw, _  = decode_tlv(seq_val, p2)
        oid = decode_oid(oid_raw)
        val = decode_value(val_tag, val_raw)
        results.append({"oid": oid, "value": val, "_end_tag": val_tag})
    return results


def parse_response(data):
    pos = 0
    _, msg_val, _ = decode_tlv(data, pos)
    pos = 0
    ver_tag, ver_raw, pos = decode_tlv(msg_val, pos)
    com_tag, com_raw, pos = decode_tlv(msg_val, pos)
    pdu_tag, pdu_val, _   = decode_tlv(msg_val, pos)

    pos2 = 0
    req_tag, req_raw, pos2 = decode_tlv(pdu_val, pos2)
    err_tag, err_raw, pos2 = decode_tlv(pdu_val, pos2)
    idx_tag, idx_raw, pos2 = decode_tlv(pdu_val, pos2)
    vbl_tag, vbl_raw, _    = decode_tlv(pdu_val, pos2)

    error_status = decode_int(err_raw)
    if error_status:
        raise RuntimeError(f"SNMP error status {error_status}")

    vbs = decode_varbinds(vbl_raw, 0, len(vbl_raw))
    return vbs


# ---------------------------------------------------------------------------
# SNMP transport
# ---------------------------------------------------------------------------

def snmp_request(host, port, community, pdu_tag, oids,
                 version=1, timeout=5, retries=2,
                 non_repeaters=0, max_repetitions=25):
    req_id = random.randint(1, 0x7FFFFFFF)
    packet = build_packet(community, pdu_tag, req_id, oids,
                          version=version,
                          non_repeaters=non_repeaters,
                          max_repetitions=max_repetitions)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for attempt in range(retries + 1):
            try:
                sock.sendto(packet, (host, port))
                resp, _ = sock.recvfrom(65535)
                return parse_response(resp)
            except socket.timeout:
                if attempt == retries:
                    raise
    finally:
        sock.close()


def do_get(host, port, community, oids, version=1, timeout=5, retries=2):
    return snmp_request(host, port, community, TAG_GETREQ, oids,
                        version=version, timeout=timeout, retries=retries)


def do_walk(host, port, community, base_oid, version=1, timeout=5, retries=2, max_rows=500):
    results   = []
    current   = base_oid
    base_parts = base_oid.strip('.')
    while True:
        vbs = snmp_request(host, port, community, TAG_GETNEXT, [current],
                           version=version, timeout=timeout, retries=retries)
        if not vbs:
            break
        vb = vbs[0]
        if vb["_end_tag"] in (TAG_NOSUCHOBJ, TAG_NOSUCHINST, TAG_ENDOFMIB):
            break
        oid = vb["oid"]
        if not oid.strip('.').startswith(base_parts):
            break
        results.append({"oid": oid, "value": vb["value"]})
        current = oid
        if len(results) >= max_rows:
            break
    return results


def do_bulk_walk(host, port, community, base_oid, version=1, timeout=5, retries=2,
                 max_rows=500, max_rep=25):
    results   = []
    current   = base_oid
    base_parts = base_oid.strip('.')
    while True:
        vbs = snmp_request(host, port, community, TAG_GETBULK, [current],
                           version=version, timeout=timeout, retries=retries,
                           non_repeaters=0, max_repetitions=max_rep)
        if not vbs:
            break
        done = False
        for vb in vbs:
            if vb["_end_tag"] in (TAG_NOSUCHOBJ, TAG_NOSUCHINST, TAG_ENDOFMIB):
                done = True
                break
            oid = vb["oid"]
            if not oid.strip('.').startswith(base_parts):
                done = True
                break
            results.append({"oid": oid, "value": vb["value"]})
            current = oid
            if len(results) >= max_rows:
                done = True
                break
        if done:
            break
    return results


# ---------------------------------------------------------------------------
# MCP helpers
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


def conn(args):
    """Extract connection params from args."""
    ver_str = str(args.get("version", "2c"))
    version = 0 if ver_str == "1" else 1  # BER version: 0=v1, 1=v2c
    return {
        "host":      args["host"],
        "port":      int(args.get("port", 161)),
        "community": args.get("community", "public"),
        "version":   version,
        "timeout":   int(args.get("timeout", 5)),
        "retries":   int(args.get("retries", 2)),
    }


# ---------------------------------------------------------------------------
# Well-known OIDs
# ---------------------------------------------------------------------------

SYSTEM_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}

IF_OIDS = {
    "ifDescr":       "1.3.6.1.2.1.2.2.1.2",
    "ifType":        "1.3.6.1.2.1.2.2.1.3",
    "ifMtu":         "1.3.6.1.2.1.2.2.1.4",
    "ifSpeed":       "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus":  "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10",
    "ifInErrors":    "1.3.6.1.2.1.2.2.1.14",
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16",
    "ifOutErrors":   "1.3.6.1.2.1.2.2.1.20",
}

IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown",
             5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


# ---------------------------------------------------------------------------
# TOOLS definition
# ---------------------------------------------------------------------------

CONN_PROPS = {
    "host":      {"type": "string",  "description": "Device IP or hostname"},
    "port":      {"type": "integer", "description": "SNMP UDP port (default 161)"},
    "version":   {"type": "string",  "description": "SNMP version: 1 or 2c (default 2c)"},
    "community": {"type": "string",  "description": "Community string (default 'public')"},
    "timeout":   {"type": "integer", "description": "Timeout seconds (default 5)"},
    "retries":   {"type": "integer", "description": "Retries (default 2)"},
}

TOOLS = [
    {
        "name": "snmp_get_system_info",
        "description": "Get system info from a device: name, description, uptime, contact, location.",
        "inputSchema": {"type": "object", "properties": CONN_PROPS, "required": ["host"]},
    },
    {
        "name": "snmp_get_interfaces",
        "description": "Get interface table: name, admin/oper status, speed, MAC, traffic counters and errors.",
        "inputSchema": {"type": "object", "properties": CONN_PROPS, "required": ["host"]},
    },
    {
        "name": "snmp_get",
        "description": "GET one or more specific OIDs from a device.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **CONN_PROPS,
                "oids": {"type": "array", "items": {"type": "string"}, "description": "OIDs to query"},
            },
            "required": ["host", "oids"],
        },
    },
    {
        "name": "snmp_walk",
        "description": "Walk an OID subtree and return all values (GETNEXT).",
        "inputSchema": {
            "type": "object",
            "properties": {
                **CONN_PROPS,
                "oid":      {"type": "string",  "description": "Base OID to walk"},
                "max_rows": {"type": "integer", "description": "Max rows (default 200)"},
            },
            "required": ["host", "oid"],
        },
    },
    {
        "name": "snmp_bulk_walk",
        "description": "Fast GETBULK walk of a large subtree (SNMPv2c only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                **CONN_PROPS,
                "oid":      {"type": "string",  "description": "Base OID to bulk-walk"},
                "max_rows": {"type": "integer", "description": "Max rows (default 500)"},
            },
            "required": ["host", "oid"],
        },
    },
    {
        "name": "snmp_get_arp_table",
        "description": "Get the ARP table (IP-to-MAC mappings) from a device.",
        "inputSchema": {"type": "object", "properties": CONN_PROPS, "required": ["host"]},
    },
    {
        "name": "snmp_get_routing_table",
        "description": "Get the IP routing table from a device.",
        "inputSchema": {"type": "object", "properties": CONN_PROPS, "required": ["host"]},
    },
    {
        "name": "snmp_get_cpu_memory",
        "description": "Get CPU and memory stats. Supports Cisco IOS, JunOS and NET-SNMP (Linux).",
        "inputSchema": {
            "type": "object",
            "properties": {
                **CONN_PROPS,
                "device_type": {"type": "string",
                                "description": "cisco | juniper | netsnmp (default netsnmp)"},
            },
            "required": ["host"],
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_snmp_get_system_info(args):
    c   = conn(args)
    vbs = do_get(c["host"], c["port"], c["community"],
                 list(SYSTEM_OIDS.values()), c["version"], c["timeout"], c["retries"])
    oid_to_name = {v: k for k, v in SYSTEM_OIDS.items()}
    result = {"host": args["host"]}
    for vb in vbs:
        name = oid_to_name.get(vb["oid"])
        if name:
            result[name] = vb["value"]
    return result


def handle_snmp_get_interfaces(args):
    c      = conn(args)
    ifaces = {}
    for col_name, base_oid in IF_OIDS.items():
        try:
            rows = do_bulk_walk(c["host"], c["port"], c["community"],
                                base_oid, c["version"], c["timeout"], c["retries"],
                                max_rows=1000)
            for row in rows:
                idx = row["oid"].split(".")[-1]
                if idx not in ifaces:
                    ifaces[idx] = {"ifIndex": int(idx)}
                val = row["value"]
                if col_name in ("ifAdminStatus", "ifOperStatus"):
                    try:
                        val = IF_STATUS.get(int(val), str(val))
                    except Exception:
                        pass
                if col_name == "ifSpeed":
                    try:
                        bps = int(val)
                        if bps >= 1_000_000_000:
                            val = f"{bps // 1_000_000_000} Gbps"
                        elif bps >= 1_000_000:
                            val = f"{bps // 1_000_000} Mbps"
                        elif bps > 0:
                            val = f"{bps // 1_000} Kbps"
                    except Exception:
                        pass
                ifaces[idx][col_name] = val
        except Exception as e:
            ifaces.setdefault("_errors", {})[col_name] = str(e)

    interfaces = sorted(ifaces.values(), key=lambda x: int(x.get("ifIndex", 0)))
    return {"host": args["host"], "interfaces": interfaces, "total": len(interfaces)}


def handle_snmp_get(args):
    c   = conn(args)
    vbs = do_get(c["host"], c["port"], c["community"],
                 args["oids"], c["version"], c["timeout"], c["retries"])
    return {"host": args["host"], "results": [{"oid": v["oid"], "value": v["value"]} for v in vbs]}


def handle_snmp_walk(args):
    c        = conn(args)
    max_rows = int(args.get("max_rows", 200))
    rows     = do_walk(c["host"], c["port"], c["community"],
                       args["oid"], c["version"], c["timeout"], c["retries"], max_rows)
    return {"host": args["host"], "oid": args["oid"], "results": rows, "count": len(rows)}


def handle_snmp_bulk_walk(args):
    c        = conn(args)
    max_rows = int(args.get("max_rows", 500))
    rows     = do_bulk_walk(c["host"], c["port"], c["community"],
                            args["oid"], c["version"], c["timeout"], c["retries"], max_rows)
    return {"host": args["host"], "oid": args["oid"], "results": rows, "count": len(rows)}


def handle_snmp_get_arp_table(args):
    c       = conn(args)
    mac_oid = "1.3.6.1.2.1.4.22.1.2"
    ip_oid  = "1.3.6.1.2.1.4.22.1.3"
    mac_rows = do_bulk_walk(c["host"], c["port"], c["community"],
                            mac_oid, c["version"], c["timeout"], c["retries"], 1000)
    ip_rows  = do_bulk_walk(c["host"], c["port"], c["community"],
                            ip_oid,  c["version"], c["timeout"], c["retries"], 1000)
    entries = {}
    for row in mac_rows:
        suffix = row["oid"][len(mac_oid):]
        entries.setdefault(suffix, {})["mac"] = row["value"]
    for row in ip_rows:
        suffix = row["oid"][len(ip_oid):]
        entries.setdefault(suffix, {})["ip"] = row["value"]
    table = sorted(
        [{"ip": v.get("ip"), "mac": v.get("mac")} for v in entries.values()],
        key=lambda x: x.get("ip", "")
    )
    return {"host": args["host"], "arp_table": table, "total": len(table)}


def handle_snmp_get_routing_table(args):
    c = conn(args)
    ROUTE_TYPE  = {1: "other", 2: "invalid", 3: "direct", 4: "indirect"}
    ROUTE_PROTO = {1: "other", 2: "local", 3: "netmgmt", 8: "egp", 11: "rip",
                   16: "ospf", 17: "bgp"}
    cols = {
        "dest":    "1.3.6.1.2.1.4.21.1.1",
        "mask":    "1.3.6.1.2.1.4.21.1.11",
        "nexthop": "1.3.6.1.2.1.4.21.1.7",
        "metric":  "1.3.6.1.2.1.4.21.1.3",
        "type":    "1.3.6.1.2.1.4.21.1.8",
        "proto":   "1.3.6.1.2.1.4.21.1.9",
        "ifindex": "1.3.6.1.2.1.4.21.1.2",
    }
    routes = {}
    for col_name, base_oid in cols.items():
        try:
            rows = do_bulk_walk(c["host"], c["port"], c["community"],
                                base_oid, c["version"], c["timeout"], c["retries"], 2000)
            for row in rows:
                key = row["oid"][len(base_oid):]
                routes.setdefault(key, {})
                val = row["value"]
                if col_name == "type":
                    try: val = ROUTE_TYPE.get(int(val), str(val))
                    except Exception: pass
                if col_name == "proto":
                    try: val = ROUTE_PROTO.get(int(val), str(val))
                    except Exception: pass
                routes[key][col_name] = val
        except Exception:
            pass
    return {"host": args["host"], "routing_table": list(routes.values()), "total": len(routes)}


def handle_snmp_get_cpu_memory(args):
    c           = conn(args)
    device_type = args.get("device_type", "netsnmp").lower()

    if device_type == "cisco":
        oid_map = {
            "cpu_5s": "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1",
            "cpu_1m": "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1",
            "cpu_5m": "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
            "mem_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
            "mem_free": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
        }
    elif device_type == "juniper":
        oid_map = {
            "cpu_idle_pct": "1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0",
            "mem_used_pct": "1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0",
        }
    else:  # netsnmp / Linux
        oid_map = {
            "cpu_user":     "1.3.6.1.4.1.2021.11.9.0",
            "cpu_system":   "1.3.6.1.4.1.2021.11.10.0",
            "cpu_idle":     "1.3.6.1.4.1.2021.11.11.0",
            "mem_total_kb": "1.3.6.1.4.1.2021.4.5.0",
            "mem_avail_kb": "1.3.6.1.4.1.2021.4.6.0",
            "swap_total_kb":"1.3.6.1.4.1.2021.4.3.0",
            "swap_avail_kb":"1.3.6.1.4.1.2021.4.4.0",
        }

    try:
        vbs = do_get(c["host"], c["port"], c["community"],
                     list(oid_map.values()), c["version"], c["timeout"], c["retries"])
    except Exception as e:
        return {"host": args["host"], "error": str(e)}

    oid_to_name = {v: k for k, v in oid_map.items()}
    result = {"host": args["host"], "device_type": device_type}
    for vb in vbs:
        name = oid_to_name.get(vb["oid"])
        if name:
            result[name] = vb["value"]

    if device_type == "netsnmp":
        try:
            used = int(result.get("cpu_user", 0))
            sys_ = int(result.get("cpu_system", 0))
            idle = int(result.get("cpu_idle", 0))
            total = used + sys_ + idle
            if total > 0:
                result["cpu_used_pct"] = round((used + sys_) / total * 100, 1)
            tot_kb  = int(result.get("mem_total_kb", 0))
            avail_kb = int(result.get("mem_avail_kb", 0))
            if tot_kb > 0:
                result["mem_used_pct"] = round((tot_kb - avail_kb) / tot_kb * 100, 1)
                result["mem_total_mb"] = round(tot_kb / 1024, 1)
                result["mem_avail_mb"] = round(avail_kb / 1024, 1)
        except Exception:
            pass

    return result


HANDLERS = {
    "snmp_get_system_info":   handle_snmp_get_system_info,
    "snmp_get_interfaces":    handle_snmp_get_interfaces,
    "snmp_get":               handle_snmp_get,
    "snmp_walk":              handle_snmp_walk,
    "snmp_bulk_walk":         handle_snmp_bulk_walk,
    "snmp_get_arp_table":     handle_snmp_get_arp_table,
    "snmp_get_routing_table": handle_snmp_get_routing_table,
    "snmp_get_cpu_memory":    handle_snmp_get_cpu_memory,
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
                "serverInfo": {"name": "snmp-mcp", "version": "1.0.0"},
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
