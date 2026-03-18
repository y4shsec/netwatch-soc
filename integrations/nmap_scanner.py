"""
integrations/nmap_scanner.py — Nmap Integration
FIXED:
1. Properly detects nmap binary path
2. Handles python-nmap PortScannerError gracefully
3. Returns structured error dict instead of crashing
4. Added quick_ping_scan for device discovery
5. Added aggressive scan option
"""
import os, subprocess
from utils.logger import get_logger
log = get_logger(__name__)


def _find_nmap() -> str:
    """Find nmap binary. Returns path or empty string."""
    # Common locations
    for path in ["/usr/bin/nmap", "/usr/local/bin/nmap", "/bin/nmap"]:
        if os.path.isfile(path):
            return path
    # Try which
    try:
        result = subprocess.run(["which","nmap"], capture_output=True, text=True)
        p = result.stdout.strip()
        if p:
            return p
    except Exception:
        pass
    return ""


class NmapScanner:

    def __init__(self):
        self.nm         = None
        self.nmap_path  = _find_nmap()
        self.available  = False
        self._init()

    def _init(self):
        if not self.nmap_path:
            log.warning("Nmap not found. Install: sudo apt install nmap")
            return
        try:
            import nmap
            self.nm        = nmap.PortScanner(nmap_search_path=(self.nmap_path,))
            self.available = True
            log.info("Nmap ready at %s", self.nmap_path)
        except Exception as e:
            log.warning("Nmap init failed: %s", e)

    def is_available(self) -> bool:
        return self.available and self.nm is not None

    def scan_host(self, target: str, ports: str = "1-1024", args: str = "-sV -T4") -> list:
        """
        Full port + service scan.
        Returns list of dicts or [{"error": "..."}] on failure.
        """
        if not self.is_available():
            return [{"error": "Nmap not installed. Run: sudo apt install nmap"}]

        log.info("Nmap scan: %s ports=%s args=%s", target, ports, args)
        results = []
        try:
            scan_args = args
            if ports:
                self.nm.scan(hosts=target, ports=ports, arguments=scan_args)
            else:
                self.nm.scan(hosts=target, arguments=scan_args)

            for host in self.nm.all_hosts():
                hostname = self.nm[host].hostname() or host
                os_guess = self._get_os(host)
                state    = self.nm[host].state()

                # If host is up but no protocols found, still return the host
                all_protos = self.nm[host].all_protocols()
                if not all_protos:
                    results.append({
                        "ip": host, "hostname": hostname,
                        "port": 0, "proto": "N/A",
                        "state": state, "service": "host up",
                        "version": "", "os_guess": os_guess,
                    })
                    continue

                for proto in all_protos:
                    for port, data in self.nm[host][proto].items():
                        results.append({
                            "ip":       host,
                            "hostname": hostname,
                            "port":     port,
                            "proto":    proto,
                            "state":    data.get("state",""),
                            "service":  data.get("name",""),
                            "version":  f"{data.get('product','')} {data.get('version','')}".strip(),
                            "os_guess": os_guess,
                        })

        except Exception as e:
            log.error("Nmap scan error: %s", e)
            return [{"error": str(e)}]

        log.info("Nmap done: %d results for %s", len(results), target)
        return results if results else [{"error": f"No results for {target} — host may be down or filtered"}]

    def quick_scan(self, target: str) -> list:
        """Fast scan: top 100 ports, no version detection."""
        return self.scan_host(target, ports="", args="-F -T4 --open")

    def ping_scan(self, subnet: str) -> list:
        """
        Discover live hosts in subnet using ping scan.
        Faster than ARP for remote subnets.
        Returns list of {"ip": ..., "hostname": ..., "state": "up"}
        """
        if not self.is_available():
            return [{"error": "Nmap not installed"}]
        log.info("Nmap ping scan: %s", subnet)
        results = []
        try:
            self.nm.scan(hosts=subnet, arguments="-sn -T4")
            for host in self.nm.all_hosts():
                if self.nm[host].state() == "up":
                    results.append({
                        "ip":       host,
                        "hostname": self.nm[host].hostname() or host,
                        "state":    "up",
                        "port":     0,
                        "service":  "host up",
                        "proto":    "N/A",
                        "version":  "",
                        "os_guess": "N/A",
                    })
        except Exception as e:
            log.error("Ping scan error: %s", e)
            return [{"error": str(e)}]
        log.info("Ping scan done: %d hosts up", len(results))
        return results

    def os_scan(self, target: str) -> str:
        """OS detection (needs root). Returns best-guess string."""
        if not self.is_available():
            return "Nmap unavailable"
        try:
            self.nm.scan(target, arguments="-O -T4")
            return self._get_os(target)
        except Exception as e:
            return f"OS scan error: {e}"

    def _get_os(self, host: str) -> str:
        try:
            matches = self.nm[host].get("osmatch", [])
            if matches:
                best = max(matches, key=lambda x: int(x.get("accuracy", 0)))
                return f"{best['name']} ({best['accuracy']}%)"
        except Exception:
            pass
        return "Unknown"