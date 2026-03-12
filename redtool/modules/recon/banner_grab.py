# modules/recon/banner_grab.py — Service banner grabber

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.module_loader import BaseModule
from core.output import info, success, warning, error, table, BOLD, RESET, CYAN, GREEN, YELLOW, DIM


# HTTP probe payload
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"

# Service-specific probes: port → bytes to send (empty = just read)
PROBES: dict[int, bytes] = {
    80:   HTTP_PROBE,
    443:  HTTP_PROBE,
    8080: HTTP_PROBE,
    8443: HTTP_PROBE,
    25:   b"",       # SMTP sends banner on connect
    21:   b"",       # FTP
    22:   b"",       # SSH
    23:   b"",       # Telnet
    110:  b"",       # POP3
    143:  b"",       # IMAP
    3306: b"",       # MySQL
    5900: b"",       # VNC
}

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5900, 8080, 8443]


def _expand_hosts(rhosts: str) -> list:
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
    if not ports_str or ports_str.lower() == "default":
        return DEFAULT_PORTS
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def _grab(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            probe = PROBES.get(port, b"")
            if probe:
                payload = probe.replace(b"{host}", host.encode())
                s.sendall(payload)
            raw = b""
            try:
                while len(raw) < 512:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    raw += chunk
            except socket.timeout:
                pass

            banner = raw.decode(errors="replace").strip()
            # Collapse whitespace / control chars for display
            banner = " ".join(banner.split())[:120]
            return {"host": host, "port": port, "banner": banner or "(no banner)"}
    except Exception:
        return None


class BannerGrab(BaseModule):
    name        = "banner_grab"
    description = "Connect to open ports and capture service banners"
    author      = "redtool"
    category    = "recon"

    def __init__(self):
        super().__init__()
        self.options = {
            "RHOSTS":  {"value": "",       "required": True,  "description": "Target IP(s) or CIDR"},
            "PORTS":   {"value": "default","required": False, "description": "Ports to probe (default: common web/mail/db)"},
            "TIMEOUT": {"value": "2",      "required": False, "description": "Connection timeout (seconds)"},
            "THREADS": {"value": "50",     "required": False, "description": "Concurrent threads"},
        }

    def run(self) -> None:
        hosts   = _expand_hosts(self.get_option("RHOSTS"))
        ports   = _parse_ports(self.get_option("PORTS") or "default")
        timeout = float(self.get_option("TIMEOUT") or 2.0)
        threads = int(self.get_option("THREADS") or 50)

        if not hosts:
            error("RHOSTS is empty or invalid.")
            return

        info(f"Grabbing banners: {len(hosts)} host(s) × {len(ports)} port(s) ({threads} threads)")

        results: list[dict] = []
        done  = 0
        total = len(hosts) * len(ports)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_grab, h, p, timeout): (h, p)
                for h in hosts for p in ports
            }
            for fut in as_completed(futures):
                done += 1
                res = fut.result()
                if res:
                    results.append(res)
                if total > 10 and done % max(1, total // 10) == 0:
                    pct = done * 100 // total
                    print(f"\r{DIM}  Progress: {pct}%{RESET}", end="", flush=True)

        if total > 10:
            print()

        if not results:
            warning("No banners grabbed (all ports closed or no response).")
            return

        results.sort(key=lambda x: (
            [int(o) for o in x["host"].split(".")] if "." in x["host"] else [x["host"]],
            x["port"]
        ))

        rows = [(r["host"], str(r["port"]), r["banner"]) for r in results]

        print(f"\n{BOLD}Banners ({len(results)}):{RESET}")
        table(["Host", "Port", "Banner"], rows)
        print()
