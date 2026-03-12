# modules/recon/portscan.py — TCP connect port scanner

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.module_loader import BaseModule
from core.output import info, success, warning, error, table, BOLD, RESET, CYAN, GREEN, RED, DIM


# Most common ports with service hints
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
]

WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt",
}


def _expand_hosts(rhosts: str) -> list:
    """Expand RHOSTS: single IP, CIDR, or comma-separated list."""
    hosts = []
    for token in rhosts.replace(" ", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            hosts.extend(str(h) for h in net.hosts())
        except ValueError:
            hosts.append(token)
    return hosts


def _parse_ports(ports_str: str) -> list:
    """Parse port spec: '22,80,443' or '1-1024' or 'common'."""
    if ports_str.lower() == "common":
        return COMMON_PORTS
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def _scan_port(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            service = WELL_KNOWN.get(port, "unknown")
            # Try banner grab (non-blocking, best effort)
            banner = ""
            try:
                s.settimeout(timeout)
                data = s.recv(256)
                banner = data.decode(errors="replace").strip().replace("\n", " ")[:60]
            except Exception:
                pass
            return {"host": host, "port": port, "service": service, "banner": banner}
    except Exception:
        return None


class PortScanner(BaseModule):
    name        = "portscan"
    description = "TCP connect port scanner with banner grab"
    author      = "redtool"
    category    = "recon"

    def __init__(self):
        super().__init__()
        self.options = {
            "RHOSTS":  {"value": "", "required": True,  "description": "Target IP(s) or CIDR (e.g. 192.168.1.0/24)"},
            "PORTS":   {"value": "common", "required": False, "description": "Ports: 'common', '22,80,443', or '1-1024'"},
            "THREADS": {"value": "100",    "required": False, "description": "Concurrent threads"},
            "TIMEOUT": {"value": "1",      "required": False, "description": "Connection timeout (seconds)"},
        }

    def run(self) -> None:
        hosts   = _expand_hosts(self.get_option("RHOSTS"))
        ports   = _parse_ports(self.get_option("PORTS") or "common")
        threads = int(self.get_option("THREADS") or 100)
        timeout = float(self.get_option("TIMEOUT") or 1.0)

        total = len(hosts) * len(ports)
        info(f"Scanning {len(hosts)} host(s), {len(ports)} port(s) — {total} probes ({threads} threads)")

        open_ports: list[dict] = []
        done = 0

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_scan_port, h, p, timeout): (h, p)
                for h in hosts for p in ports
            }
            for fut in as_completed(futures):
                done += 1
                result = fut.result()
                if result:
                    open_ports.append(result)
                # Progress every 10 %
                if total > 10 and done % max(1, total // 10) == 0:
                    pct = done * 100 // total
                    print(f"\r{DIM}  Progress: {pct}%{RESET}", end="", flush=True)

        if total > 10:
            print()  # newline after progress

        if not open_ports:
            warning("No open ports found.")
            return

        # Sort by host then port
        open_ports.sort(key=lambda x: (
            [int(o) for o in x["host"].split(".")] if "." in x["host"] else [x["host"]],
            x["port"]
        ))

        rows = [
            (
                r["host"],
                str(r["port"]),
                r["service"],
                f"{GREEN}OPEN{RESET}",
                r["banner"],
            )
            for r in open_ports
        ]

        print(f"\n{BOLD}Open ports ({len(open_ports)}):{RESET}")
        table(["Host", "Port", "Service", "State", "Banner"], rows)
        print()
