"""
core/network_scanner.py — Device Discovery
FIXED:
1. iface= passed to srp() explicitly (required for WiFi)
2. Fallback: if ARP returns 0, try nmap ping scan
3. Reads config.SUBNET/INTERFACE at scan time (not at import time)
4. Better error messages with exact subnet + interface shown
"""
import threading, time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import config
from utils.logger import get_logger
from utils.network_utils import get_hostname, get_mac_vendor

log = get_logger(__name__)


@dataclass
class DeviceInfo:
    ip:         str
    mac:        str
    hostname:   str   = "N/A"
    vendor:     str   = "Unknown"
    os_hint:    str   = "N/A"
    ports:      list  = None
    first_seen: float = 0.0
    last_seen:  float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ports"] = self.ports or []
        return d


class NetworkScanner:

    def __init__(self, subnet: str = None, interface: str = None, interval: int = 60):
        # None = read from config at scan time (so main.py can patch config first)
        self._subnet    = subnet
        self._interface = interface
        self.interval   = interval
        self._devices: Dict[str, DeviceInfo] = {}
        self._lock    = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_new_device = []

    @property
    def subnet(self) -> str:
        return self._subnet or config.SUBNET

    @property
    def interface(self) -> str:
        return self._interface or config.INTERFACE

    def on_new_device(self, fn):
        self._on_new_device.append(fn)

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        log.info("Scanner started | subnet: %s | iface: %s", self.subnet, self.interface)

    def stop(self) -> None:
        self._running = False

    def get_devices(self) -> List[DeviceInfo]:
        with self._lock:
            return list(self._devices.values())

    def scan_now(self) -> List[DeviceInfo]:
        return self._scan()

    def _loop(self) -> None:
        while self._running:
            self._scan()
            for _ in range(self.interval * 2):
                if not self._running: break
                time.sleep(0.5)

    def _scan(self) -> List[DeviceInfo]:
        """Try ARP scan first. Fall back to nmap ping scan."""
        found = self._arp_scan()
        if not found:
            log.warning("ARP returned 0 devices — trying nmap ping scan as fallback")
            found = self._nmap_ping_fallback()
        return found

    def _arp_scan(self) -> List[DeviceInfo]:
        subnet    = self.subnet
        interface = self.interface
        log.info("ARP scan | subnet: %s | iface: %s", subnet, interface)
        found = []

        try:
            from scapy.all import ARP, Ether, srp

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, unanswered = srp(
                pkt,
                iface   = interface,   # MUST specify for WiFi
                timeout = 5,
                verbose = 0,
                retry   = 2,
            )

            log.info("ARP: %d answered, %d unanswered", len(answered), len(unanswered))

            now = time.time()
            for _, resp in answered:
                ip  = resp[ARP].psrc
                mac = resp[ARP].hwsrc.upper()
                found.append(self._register_device(ip, mac, now))

        except PermissionError:
            log.error("ARP scan needs root: sudo -E env PATH=$PATH python3 main.py")
        except OSError as e:
            log.error("ARP OSError (iface=%s subnet=%s): %s", interface, subnet, e)
        except Exception as e:
            log.error("ARP scan error: %s", e)

        log.info("ARP complete: %d devices", len(found))
        return [d for d in found if d]

    def _nmap_ping_fallback(self) -> List[DeviceInfo]:
        """Use nmap -sn to discover hosts when ARP fails."""
        subnet = self.subnet
        log.info("Nmap ping scan fallback: %s", subnet)
        found = []
        try:
            from integrations.nmap_scanner import NmapScanner
            nm = NmapScanner()
            if not nm.is_available():
                log.warning("Nmap not available for fallback scan")
                return []
            results = nm.ping_scan(subnet)
            now     = time.time()
            for r in results:
                if "error" not in r and r.get("ip"):
                    dev = self._register_device(r["ip"], "00:00:00:00:00:00", now)
                    if dev: found.append(dev)
        except Exception as e:
            log.error("Nmap fallback error: %s", e)
        log.info("Nmap fallback: %d hosts", len(found))
        return found

    def _register_device(self, ip: str, mac: str, now: float) -> Optional[DeviceInfo]:
        with self._lock:
            if ip not in self._devices:
                dev = DeviceInfo(ip=ip, mac=mac, first_seen=now, last_seen=now)
                self._devices[ip] = dev
                threading.Thread(target=self._enrich, args=(dev,), daemon=True).start()
                for cb in self._on_new_device:
                    try: cb(dev)
                    except Exception: pass
                log.info("New device: %s  MAC: %s", ip, mac)
            else:
                self._devices[ip].last_seen = now
                if mac != "00:00:00:00:00:00":
                    self._devices[ip].mac = mac
        return self._devices.get(ip)

    def _enrich(self, dev: DeviceInfo) -> None:
        try: dev.hostname = get_hostname(dev.ip)
        except Exception: pass
        try: dev.vendor = get_mac_vendor(dev.mac)
        except Exception: pass