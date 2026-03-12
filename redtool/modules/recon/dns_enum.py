# modules/recon/dns_enum.py — DNS enumeration

import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.module_loader import BaseModule
from core.output import info, success, warning, error, table, BOLD, RESET, CYAN, GREEN, DIM


# Default subdomain wordlist for brute-force
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin",
    "vpn", "ns1", "ns2", "mx", "api", "dev", "staging", "test", "blog",
    "shop", "portal", "remote", "citrix", "gitlab", "jenkins", "jira",
    "confluence", "wiki", "intranet", "sso", "ldap", "exchange",
    "autodiscover", "owa", "cpanel", "whm", "panel", "dashboard",
    "monitor", "status", "cdn", "assets", "static", "media", "img",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolve(host: str) -> list:
    """Resolve a hostname to IPs (A/AAAA)."""
    try:
        results = socket.getaddrinfo(host, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def _dig(domain: str, rtype: str) -> list:
    """Run dig/nslookup if available, else fallback to socket."""
    if shutil.which("dig"):
        try:
            out = subprocess.check_output(
                ["dig", "+short", rtype, domain],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode(errors="replace").strip()
            return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception:
            return []
    elif shutil.which("nslookup"):
        try:
            out = subprocess.check_output(
                ["nslookup", "-type=" + rtype, domain],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode(errors="replace")
            # Parse nslookup output naively
            results = []
            for line in out.splitlines():
                line = line.strip()
                if "=" in line or "address" in line.lower():
                    parts = line.split()
                    if parts:
                        results.append(parts[-1])
            return results
        except Exception:
            return []
    # Fallback: only A records via socket
    if rtype == "A":
        return _resolve(domain)
    return []


def _brute_subdomain(domain: str, sub: str) -> dict | None:
    fqdn = f"{sub}.{domain}"
    ips = _resolve(fqdn)
    if ips:
        return {"subdomain": fqdn, "ips": ", ".join(ips)}
    return None


class DnsEnum(BaseModule):
    name        = "dns_enum"
    description = "DNS enumeration: record lookup and subdomain brute-force"
    author      = "redtool"
    category    = "recon"

    def __init__(self):
        super().__init__()
        self.options = {
            "DOMAIN":  {"value": "",    "required": True,  "description": "Target domain (e.g. example.com)"},
            "BRUTEFORCE": {"value": "true", "required": False, "description": "Enable subdomain brute-force (true/false)"},
            "WORDLIST": {"value": "",   "required": False, "description": "Path to subdomain wordlist (blank = built-in)"},
            "THREADS":  {"value": "30", "required": False, "description": "Threads for brute-force"},
        }

    def run(self) -> None:
        domain     = self.get_option("DOMAIN").strip().rstrip(".")
        bruteforce = self.get_option("BRUTEFORCE").lower() not in ("false", "0", "no")
        wordlist_path = self.get_option("WORDLIST")
        threads    = int(self.get_option("THREADS") or 30)

        if not domain:
            error("DOMAIN is required.")
            return

        # --- DNS records ---
        print(f"\n{BOLD}DNS records for {CYAN}{domain}{RESET}{BOLD}:{RESET}")
        record_rows = []
        for rtype in RECORD_TYPES:
            results = _dig(domain, rtype)
            for r in results:
                record_rows.append((rtype, r))

        if record_rows:
            table(["Type", "Value"], record_rows)
        else:
            warning("No DNS records found (or dig/nslookup unavailable).")
        print()

        # --- Subdomain brute-force ---
        if not bruteforce:
            return

        wordlist = DEFAULT_WORDLIST
        if wordlist_path:
            try:
                with open(wordlist_path) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
                info(f"Using wordlist: {wordlist_path} ({len(wordlist)} entries)")
            except OSError as e:
                error(f"Cannot open wordlist: {e}")
                return
        else:
            info(f"Using built-in wordlist ({len(wordlist)} entries)")

        info(f"Brute-forcing subdomains with {threads} threads...")
        found: list[dict] = []
        done = 0
        total = len(wordlist)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_brute_subdomain, domain, sub): sub for sub in wordlist}
            for fut in as_completed(futures):
                done += 1
                res = fut.result()
                if res:
                    found.append(res)
                    print(f"  {GREEN}[+]{RESET} {res['subdomain']:40s} {res['ips']}")
                if total > 10 and done % max(1, total // 10) == 0:
                    pct = done * 100 // total
                    print(f"\r{DIM}  Progress: {pct}% ({done}/{total}){RESET}", end="", flush=True)

        if total > 10:
            print()

        if not found:
            warning("No subdomains discovered.")
            return

        found.sort(key=lambda x: x["subdomain"])
        print(f"\n{BOLD}Discovered subdomains ({len(found)}):{RESET}")
        table(["Subdomain", "IP(s)"], [(s["subdomain"], s["ips"]) for s in found])
        print()
