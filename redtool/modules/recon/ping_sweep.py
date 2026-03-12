# modules/recon/ping_sweep.py — ICMP ping sweep

import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.module_loader import BaseModule
from core.output import info, success, warning, error, table, BOLD, RESET, GREEN, RED, DIM


def _expand_network(cidr: str) -> list:
    hosts = []
    for token in cidr.replace(" ", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            if net.num_addresses == 1:
                hosts.append(str(net.network_address))
            else:
                hosts.extend(str(h) for h in net.hosts())
        except ValueError:
            hosts.append(token)
    return hosts


def _ping(host: str, timeout: int, count: int) -> dict:
    """Ping a single host. Returns dict with host and alive flag."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), "-q", host]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout * count + 2,
        )
        alive = result.returncode == 0
        # Extract RTT from output if alive
        rtt = ""
        if alive:
            out = result.stdout.decode(errors="replace")
            for line in out.splitlines():
                if "rtt" in line or "round-trip" in line:
                    # typical: rtt min/avg/max/mdev = 0.3/0.4/0.5/0.1 ms
                    parts = line.split("=")
                    if len(parts) > 1:
                        rtt = parts[1].strip().split("/")[1] + " ms" if "/" in parts[1] else parts[1].strip()
                    break
                elif "Average" in line:  # Windows
                    rtt = line.split("=")[-1].strip() if "=" in line else ""
                    break
        return {"host": host, "alive": alive, "rtt": rtt}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"host": host, "alive": False, "rtt": ""}


class PingSweep(BaseModule):
    name        = "ping_sweep"
    description = "ICMP ping sweep to discover live hosts in a subnet"
    author      = "redtool"
    category    = "recon"

    def __init__(self):
        super().__init__()
        self.options = {
            "RHOSTS":  {"value": "",  "required": True,  "description": "Target CIDR or IP list (e.g. 192.168.1.0/24)"},
            "TIMEOUT": {"value": "1", "required": False, "description": "Ping timeout per host (seconds)"},
            "COUNT":   {"value": "1", "required": False, "description": "Ping packets per host"},
            "THREADS": {"value": "50","required": False, "description": "Concurrent threads"},
        }

    def run(self) -> None:
        hosts   = _expand_network(self.get_option("RHOSTS"))
        timeout = int(self.get_option("TIMEOUT") or 1)
        count   = int(self.get_option("COUNT") or 1)
        threads = int(self.get_option("THREADS") or 50)

        if not hosts:
            error("RHOSTS is empty or invalid.")
            return

        info(f"Sweeping {len(hosts)} host(s) with {threads} threads (timeout={timeout}s)")

        alive_hosts: list[dict] = []
        done = 0
        total = len(hosts)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_ping, h, timeout, count): h for h in hosts}
            for fut in as_completed(futures):
                done += 1
                res = fut.result()
                if res["alive"]:
                    alive_hosts.append(res)
                if total > 5 and done % max(1, total // 10) == 0:
                    pct = done * 100 // total
                    print(f"\r{DIM}  Progress: {pct}% ({done}/{total}){RESET}", end="", flush=True)

        if total > 5:
            print()

        if not alive_hosts:
            warning("No live hosts found.")
            return

        alive_hosts.sort(key=lambda x: (
            [int(o) for o in x["host"].split(".")] if "." in x["host"] else [x["host"]]
        ))

        rows = [(h["host"], f"{GREEN}UP{RESET}", h["rtt"] or "-") for h in alive_hosts]

        print(f"\n{BOLD}Live hosts ({len(alive_hosts)}/{total}):{RESET}")
        table(["Host", "Status", "Avg RTT"], rows)
        print()

        success(f"{len(alive_hosts)} host(s) alive out of {total} scanned.")
