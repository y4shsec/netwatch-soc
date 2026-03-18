"""
core/network_intelligence.py — Professional Network Intelligence Engine
=========================================================================
Auto-detects:
  - Best network interface (WiFi/Ethernet priority)
  - Local IP + Subnet CIDR
  - Gateway IP
  - DNS servers

Then performs deep device discovery:
  - ARP scan → all live IPs + MACs
  - MAC OUI → vendor/brand (Apple, Samsung, Cisco etc.)
  - Reverse DNS → hostnames
  - Nmap OS detection → OS family + version
  - Nmap service scan → open ports + running services
  - DNS traffic analysis → active apps per device

Architecture:
  NetworkIntelligence.scan_network()
      ├── _detect_local_info()       # interface + subnet + gateway
      ├── _arp_sweep()               # find all live IPs
      ├── _enrich_basic()            # MAC vendor + hostname (fast)
      ├── _nmap_deep_scan()          # OS + ports + services (slow, parallel)
      └── _dns_app_tracker()         # track app usage from DNS queries
"""

import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

import psutil

import config
from utils.logger import get_logger

log = get_logger(__name__)


# ─── OUI Database (top 200 vendors) ──────────────────────────────────────────
# Maps first 3 bytes of MAC → vendor name
# Full offline DB: pip install netaddr  OR use manuf file from Wireshark
OUI_MAP = {
    "00:50:56": "VMware",         "00:0C:29": "VMware",
    "00:1A:11": "Google",         "F4:F5:D8": "Google",
    "AC:D1:B8": "Apple",          "F0:18:98": "Apple",
    "3C:22:FB": "Apple",          "A4:C3:F0": "Apple",
    "BC:3B:AF": "Apple",          "70:70:0D": "Apple",
    "00:17:88": "Philips Hue",    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",   "E4:5F:01": "Raspberry Pi",
    "00:1B:44": "SanDisk",        "18:FE:34": "Espressif (IoT)",
    "24:62:AB": "Espressif (IoT)","A4:CF:12": "Espressif (IoT)",
    "CC:50:E3": "Espressif (IoT)","30:AE:A4": "Espressif (IoT)",
    "FC:F5:C4": "Espressif (IoT)","74:DA:EA": "Espressif (IoT)",
    "58:BF:25": "Espressif (IoT)","10:52:1C": "Espressif (IoT)",
    "00:1E:58": "D-Link",         "1C:7E:E5": "D-Link",
    "00:26:5A": "D-Link",         "B0:48:7A": "D-Link",
    "00:1D:0F": "TP-Link",        "50:C7:BF": "TP-Link",
    "B0:BE:76": "TP-Link",        "98:DA:C4": "TP-Link",
    "54:AF:97": "TP-Link",        "C4:E9:84": "TP-Link",
    "00:00:0C": "Cisco",          "00:1B:D4": "Cisco",
    "00:13:80": "Cisco",          "58:97:BD": "Cisco",
    "70:69:5A": "Cisco",          "3C:08:F6": "Cisco",
    "F8:72:EA": "Cisco",          "00:E0:4C": "Realtek",
    "52:54:00": "QEMU/KVM",       "08:00:27": "VirtualBox",
    "00:25:90": "Super Micro",    "D4:3D:7E": "Dell",
    "00:21:9B": "Dell",           "F8:BC:12": "Dell",
    "00:14:22": "Dell",           "18:03:73": "Dell",
    "00:1C:23": "HP",             "3C:D9:2B": "HP",
    "FC:15:B4": "HP",             "94:57:A5": "HP",
    "00:18:71": "HP",             "00:22:64": "HP",
    "28:D2:44": "Microsoft",      "00:50:F2": "Microsoft",
    "7C:1E:52": "Microsoft",      "00:15:5D": "Microsoft (Hyper-V)",
    "28:16:AD": "Samsung",        "A0:07:98": "Samsung",
    "F4:7B:5E": "Samsung",        "8C:71:F8": "Samsung",
    "CC:07:AB": "Samsung",        "04:92:26": "Samsung",
    "78:BD:BC": "Samsung",        "54:40:AD": "Samsung",
    "00:16:6B": "LG Electronics", "AC:F7:F3": "LG Electronics",
    "64:BC:0C": "LG Electronics", "CC:2D:83": "LG Electronics",
    "04:D3:B0": "Huawei",         "00:46:4B": "Huawei",
    "54:89:98": "Huawei",         "70:72:CF": "Huawei",
    "9C:74:1A": "Huawei",         "F4:8E:38": "Huawei",
    "00:1E:10": "Xiaomi",         "F8:A4:5F": "Xiaomi",
    "64:09:80": "Xiaomi",         "28:6C:07": "Xiaomi",
    "74:23:44": "Xiaomi",         "FC:64:BA": "Xiaomi",
    "6C:72:20": "OnePlus",        "8C:79:F0": "OnePlus",
    "44:D4:E0": "OnePlus",        "AC:37:43": "HTC",
    "00:17:BB": "NETGEAR",        "20:E5:2A": "NETGEAR",
    "C4:04:15": "NETGEAR",        "10:DA:43": "NETGEAR",
    "2C:27:D7": "NETGEAR",        "A0:40:A0": "NETGEAR",
    "00:18:4D": "NETGEAR",        "9C:3D:CF": "NETGEAR",
    "00:1A:70": "Ubiquiti",       "04:18:D6": "Ubiquiti",
    "78:8A:20": "Ubiquiti",       "DC:9F:DB": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",       "18:E8:29": "Ubiquiti",
    "00:0B:86": "Aruba Networks", "00:24:6C": "Aruba Networks",
    "94:B4:0F": "Aruba Networks", "AC:A3:1E": "Aruba Networks",
    "58:61:63": "Aruba Networks", "00:1C:B3": "Apple Airport",
    "28:CF:E9": "Apple",          "68:A8:6D": "Apple",
    "60:F8:1D": "Apple",          "78:4F:43": "Apple",
    "00:03:7F": "Atheros Comm.",  "00:0F:B5": "Netgear",
    "2C:6D:C1": "Unknown Android","EC:4C:8C": "Unknown Android",
    "44:38:E8": "Amazon",         "FC:A1:83": "Amazon Echo",
    "34:D2:70": "Amazon",         "84:D6:D0": "Amazon",
    "00:FC:8B": "Amazon",         "38:F7:3D": "Amazon",
    "F0:27:2D": "Amazon",         "68:37:E9": "Amazon",
    "B4:7C:9C": "Amazon Kindle",  "74:75:48": "Amazon",
    "00:90:4C": "Epson",          "00:26:AB": "Epson",
    "00:1B:A9": "Brother",        "00:80:77": "Brother",
    "00:00:48": "Epson",          "08:00:20": "Sun Microsystems",
    "00:03:BA": "Sun Microsystems","00:07:E9": "Intel",
    "00:12:F0": "Intel",          "00:1B:21": "Intel",
    "78:2B:CB": "Intel",          "AC:FD:CE": "Intel",
}

# ─── App Detection via DNS + Port ─────────────────────────────────────────────
# Maps DNS domain patterns → App name
APP_DNS_PATTERNS = {
    "youtube": "YouTube",           "ytimg": "YouTube",
    "googlevideo": "YouTube",       "ggpht": "YouTube",
    "whatsapp": "WhatsApp",         "wa.me": "WhatsApp",
    "instagram": "Instagram",       "cdninstagram": "Instagram",
    "facebook": "Facebook",         "fbcdn": "Facebook",
    "fbsbx": "Facebook",            "twitter": "Twitter/X",
    "twimg": "Twitter/X",           "x.com": "Twitter/X",
    "tiktok": "TikTok",             "tiktokcdn": "TikTok",
    "spotify": "Spotify",           "scdn.co": "Spotify",
    "netflix": "Netflix",           "nflxext": "Netflix",
    "nflxso": "Netflix",            "hotstar": "Hotstar",
    "primevideo": "Amazon Prime",   "cloudfront": "AWS/CDN",
    "akamai": "CDN/Streaming",      "akamaitech": "CDN/Streaming",
    "snapchat": "Snapchat",         "sc-cdn": "Snapchat",
    "zoom": "Zoom",                 "zoomgov": "Zoom",
    "teams": "Microsoft Teams",     "skype": "Skype",
    "discord": "Discord",           "discordapp": "Discord",
    "telegram": "Telegram",         "t.me": "Telegram",
    "gmail": "Gmail",               "googlemail": "Gmail",
    "outlook": "Outlook/Email",     "office365": "Microsoft Office",
    "microsoftonline": "Microsoft", "windows": "Windows Update",
    "windowsupdate": "Windows Update","apple": "Apple Services",
    "icloud": "iCloud",             "itunes": "App Store",
    "google.com": "Google Search",  "googleapis": "Google APIs",
    "gstatic": "Google Static",     "chrome": "Chrome Browser",
    "play.google": "Google Play",   "android": "Android Services",
    "pubg": "PUBG Mobile",          "freefire": "Free Fire",
    "roblox": "Roblox",             "minecraft": "Minecraft",
    "valorant": "Valorant",         "epicgames": "Epic Games",
    "steam": "Steam",               "steampowered": "Steam",
    "linkedin": "LinkedIn",         "paytm": "Paytm",
    "phonepe": "PhonePe",           "upi": "UPI Payment",
    "razorpay": "Razorpay",         "flipkart": "Flipkart",
    "amazon.in": "Amazon India",    "myntra": "Myntra",
    "swiggy": "Swiggy",             "zomato": "Zomato",
    "ola": "Ola Cabs",              "uber": "Uber",
    "hotstar": "Disney+ Hotstar",   "jio": "Jio Services",
    "airtel": "Airtel Services",
}

# Port → Service name (extended)
PORT_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    194: "IRC", 389: "LDAP", 443: "HTTPS/TLS", 445: "SMB",
    465: "SMTP-SSL", 514: "Syslog", 515: "LPD Printing",
    587: "SMTP-TLS", 631: "IPP Printing", 636: "LDAPS",
    993: "IMAP-SSL", 995: "POP3-SSL", 1080: "SOCKS Proxy",
    1194: "OpenVPN", 1433: "MS SQL Server", 1521: "Oracle DB",
    1723: "PPTP VPN", 2082: "cPanel", 2083: "cPanel SSL",
    3000: "Dev Server", 3306: "MySQL", 3389: "RDP (Windows)",
    3478: "STUN/TURN", 4000: "Dev Server", 4443: "Alt HTTPS",
    5000: "Flask/Dev", 5222: "XMPP/Chat", 5353: "mDNS",
    5432: "PostgreSQL", 5900: "VNC Remote", 6379: "Redis",
    6881: "BitTorrent", 7000: "Cassandra", 8080: "HTTP Alt",
    8443: "HTTPS Alt", 8888: "Jupyter", 9000: "PHP-FPM",
    9200: "Elasticsearch", 9300: "Elasticsearch", 10000: "Webmin",
    27017: "MongoDB", 27018: "MongoDB", 50070: "Hadoop",
    5601: "Kibana", 3000: "Grafana/Node",
}

# OS detection hints from TTL
TTL_OS_MAP = {
    (0, 64):   "Linux / Android / macOS",
    (65, 128): "Windows",
    (129, 255):"Network Device / Router (Cisco/Juniper)",
}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class NetworkInfo:
    """Local machine's network configuration."""
    interface:   str   = ""
    local_ip:    str   = ""
    subnet_cidr: str   = ""
    netmask:     str   = ""
    gateway:     str   = ""
    dns_servers: list  = field(default_factory=list)
    mac_address: str   = ""
    network_type:str   = ""   # Home / Office / Public WiFi

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeviceDetail:
    """Detailed information about a discovered network device."""
    ip:           str   = ""
    mac:          str   = ""
    vendor:       str   = "Unknown"
    hostname:     str   = "N/A"
    device_type:  str   = "Unknown"    # Router, Phone, PC, Laptop, IoT, Server
    os_family:    str   = "Unknown"    # Windows, Linux, Android, iOS, macOS
    os_version:   str   = ""
    os_confidence:str   = ""
    open_ports:   list  = field(default_factory=list)
    services:     list  = field(default_factory=list)   # [{port, name, version}]
    active_apps:  list  = field(default_factory=list)   # YouTube, WhatsApp, etc.
    ttl_hint:     str   = ""
    first_seen:   float = 0.0
    last_seen:    float = 0.0
    scan_complete:bool  = False

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ─── Main Engine ──────────────────────────────────────────────────────────────

class NetworkIntelligence:
    """
    Professional network intelligence engine.
    
    Usage:
        ni = NetworkIntelligence()
        net_info = ni.detect_local_network()   # Step 1: detect our own network
        devices  = ni.scan_all_devices()       # Step 2: scan all devices (slow)
        
        # Or incremental:
        ni.start_background_scan()             # Non-blocking
        devices = ni.get_devices()             # Get results as they come in
    """

    def __init__(self):
        self.net_info:    Optional[NetworkInfo]      = None
        self._devices:    Dict[str, DeviceDetail]    = {}
        self._lock        = threading.Lock()
        self._running     = False
        self._callbacks   = []   # Called when new device info arrives
        # DNS app tracker: ip → set of app names
        self._app_cache:  Dict[str, set]             = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def detect_local_network(self) -> NetworkInfo:
        """
        Detect the local machine's network configuration.
        Returns NetworkInfo with interface, IP, subnet, gateway, DNS.
        """
        ni = NetworkInfo()
        ni.interface    = config.INTERFACE
        ni.local_ip     = self._get_local_ip()
        ni.subnet_cidr  = config.SUBNET
        ni.mac_address  = self._get_mac(config.INTERFACE)
        ni.gateway      = self._detect_gateway()
        ni.dns_servers  = self._detect_dns_servers()
        ni.network_type = self._guess_network_type(ni)
        self.net_info   = ni
        log.info("Local network: %s on %s (%s)", ni.local_ip, ni.interface, ni.subnet_cidr)
        return ni

    def scan_all_devices(self,
                         deep_scan: bool = True,
                         max_workers: int = 10,
                         progress_cb = None) -> List[DeviceDetail]:
        """
        Full network scan:
          1. ARP sweep → find all live IPs
          2. Basic enrichment (vendor + hostname) in parallel
          3. Nmap deep scan (OS + ports + services) in parallel
        
        deep_scan=True → Nmap scan (slower, ~2-5 min for /23 subnet)
        deep_scan=False → ARP only (fast, ~10 seconds)
        progress_cb → called with (done, total, current_ip)
        """
        log.info("Starting full network scan on %s", config.SUBNET)

        # Step 1: ARP sweep
        live_ips = self._arp_sweep()
        log.info("ARP found %d live hosts", len(live_ips))

        if not live_ips:
            log.warning("No hosts found via ARP — trying Nmap ping scan")
            live_ips = self._nmap_ping_fallback()

        total = len(live_ips)
        done  = [0]

        # Step 2: Basic enrichment (fast — parallel)
        def enrich_basic(entry):
            ip, mac, ttl = entry
            dev = self._get_or_create(ip, mac, ttl)
            dev.vendor   = self._lookup_vendor(mac)
            dev.hostname = self._reverse_dns(ip)
            dev.device_type = self._guess_device_type(dev.vendor, dev.hostname, dev.open_ports)
            dev.ttl_hint = self._ttl_to_os(ttl)
            done[0] += 1
            if progress_cb:
                progress_cb(done[0], total, ip)
            self._notify(dev)
            return dev

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(as_completed([ex.submit(enrich_basic, e) for e in live_ips]))

        # Step 3: Deep Nmap scan (slow — parallel with fewer workers)
        if deep_scan:
            log.info("Starting Nmap deep scan on %d hosts ...", len(live_ips))
            ips = [e[0] for e in live_ips]

            def nmap_scan(ip):
                self._nmap_deep(ip)
                done[0] += 1
                if progress_cb:
                    progress_cb(done[0], total + len(ips), ip)

            done[0] = total   # reset counter for nmap phase
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                list(as_completed([ex.submit(nmap_scan, ip) for ip in ips]))

        return self.get_devices()

    def start_background_scan(self, deep_scan: bool = True):
        """Non-blocking scan — results available via get_devices() / callbacks."""
        self._running = True
        t = threading.Thread(
            target=self.scan_all_devices,
            kwargs={"deep_scan": deep_scan},
            daemon=True
        )
        t.start()

    def get_devices(self) -> List[DeviceDetail]:
        with self._lock:
            return sorted(self._devices.values(), key=lambda d: self._ip_sort_key(d.ip))

    def on_device_update(self, fn):
        """Register callback for when device info is updated."""
        self._callbacks.append(fn)

    def update_app_from_dns(self, src_ip: str, dns_query: str):
        """
        Called by packet sniffer when a DNS query is seen.
        Adds detected app to the source IP's active_apps list.
        """
        if not dns_query:
            return
        app = self._dns_to_app(dns_query)
        if not app:
            return
        if src_ip not in self._app_cache:
            self._app_cache[src_ip] = set()
        if app not in self._app_cache[src_ip]:
            self._app_cache[src_ip].add(app)
            with self._lock:
                if src_ip in self._devices:
                    dev = self._devices[src_ip]
                    if app not in dev.active_apps:
                        dev.active_apps.append(app)
                        self._notify(dev)

    # ── Network Info Helpers ──────────────────────────────────────────────────

    def _get_local_ip(self) -> str:
        try:
            addrs = psutil.net_if_addrs().get(config.INTERFACE, [])
            for addr in addrs:
                if addr.family == 2:   # AF_INET
                    return addr.address
        except Exception:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _get_mac(self, iface: str) -> str:
        try:
            addrs = psutil.net_if_addrs().get(iface, [])
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    return addr.address.upper()
        except Exception:
            pass
        return "N/A"

    def _detect_gateway(self) -> str:
        """Read default gateway from routing table."""
        try:
            # Linux: read /proc/net/route
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if parts[1] == "00000000":   # destination = 0.0.0.0 = default route
                        gw_hex = parts[2]
                        gw_int = int(gw_hex, 16)
                        gw_ip  = socket.inet_ntoa(struct.pack("<I", gw_int))
                        if gw_ip != "0.0.0.0":
                            log.info("Gateway detected: %s", gw_ip)
                            return gw_ip
        except Exception:
            pass
        # Fallback: assume .1 of subnet
        try:
            net = config.SUBNET.rsplit(".", 1)[0]
            return f"{net}.1"
        except Exception:
            return "192.168.1.1"

    def _detect_dns_servers(self) -> List[str]:
        """Read DNS servers from /etc/resolv.conf."""
        dns = []
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        ip = line.split()[1].strip()
                        if ip not in dns:
                            dns.append(ip)
        except Exception:
            pass
        return dns or ["8.8.8.8"]

    def _guess_network_type(self, ni: NetworkInfo) -> str:
        """Guess network type from IP range."""
        ip = ni.local_ip
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            # Count devices for guess
            cidr_bits = int(ni.subnet_cidr.split("/")[1]) if "/" in ni.subnet_cidr else 24
            if cidr_bits >= 24:
                return "Home Network"
            elif cidr_bits >= 22:
                return "Office / Enterprise Network"
            else:
                return "Large Enterprise / Campus Network"
        return "Public / Routed Network"

    # ── ARP Sweep ─────────────────────────────────────────────────────────────

    def _arp_sweep(self) -> List[Tuple[str, str, int]]:
        """
        ARP broadcast scan. Returns list of (ip, mac, ttl) tuples.
        TTL from the IP header gives us OS hints.
        """
        results = []
        try:
            from scapy.all import ARP, Ether, IP, srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=config.SUBNET)
            answered, _ = srp(
                pkt,
                iface   = config.INTERFACE,
                timeout = 5,
                verbose = 0,
                retry   = 2,
            )
            now = time.time()
            for _, resp in answered:
                ip  = resp[ARP].psrc
                mac = resp[ARP].hwsrc.upper()
                ttl = resp[IP].ttl if IP in resp else 64
                results.append((ip, mac, ttl))
                with self._lock:
                    if ip not in self._devices:
                        self._devices[ip] = DeviceDetail(
                            ip=ip, mac=mac,
                            ttl_hint=self._ttl_to_os(ttl),
                            first_seen=now, last_seen=now
                        )
                    else:
                        self._devices[ip].last_seen = now
        except Exception as e:
            log.error("ARP sweep error: %s", e)
        return results

    def _nmap_ping_fallback(self) -> List[Tuple[str, str, int]]:
        """Use nmap -sn when ARP fails."""
        results = []
        try:
            from integrations.nmap_scanner import NmapScanner
            nm = NmapScanner()
            if nm.is_available():
                for r in nm.ping_scan(config.SUBNET):
                    if "error" not in r and r.get("ip"):
                        results.append((r["ip"], "00:00:00:00:00:00", 64))
        except Exception as e:
            log.error("Nmap fallback error: %s", e)
        return results

    # ── Deep Enrichment ───────────────────────────────────────────────────────

    def _nmap_deep(self, ip: str):
        """
        Run Nmap on a single IP: OS detection + service scan.
        Updates the DeviceDetail for that IP.
        """
        try:
            import nmap as nmap_lib
            nm = nmap_lib.PortScanner()

            # -sV: service version, -O: OS detect, -T4: fast timing
            # --top-ports 50: scan most common 50 ports only
            # Skip OS detection if not root (it requires raw sockets)
            nm.scan(
                hosts=ip,
                arguments="-sV -T4 --top-ports 50 --open"
            )

            if ip not in nm.all_hosts():
                return

            host_data = nm[ip]
            with self._lock:
                if ip not in self._devices:
                    self._devices[ip] = DeviceDetail(ip=ip)
                dev = self._devices[ip]

            # OS detection
            os_matches = host_data.get("osmatch", [])
            if os_matches:
                best_os = max(os_matches, key=lambda x: int(x.get("accuracy", 0)))
                dev.os_version    = best_os.get("name", "Unknown")
                dev.os_confidence = f"{best_os.get('accuracy', '?')}%"
                dev.os_family     = self._parse_os_family(best_os.get("name", ""))
            elif dev.ttl_hint:
                dev.os_family = dev.ttl_hint   # Use TTL hint as fallback

            # Ports + services
            ports    = []
            services = []
            for proto in host_data.all_protocols():
                for port, pdata in host_data[proto].items():
                    if pdata.get("state") == "open":
                        ports.append(port)
                        svc_name = pdata.get("name", PORT_SERVICES.get(port, "unknown"))
                        version  = f"{pdata.get('product','')} {pdata.get('version','')}".strip()
                        services.append({
                            "port":    port,
                            "proto":   proto,
                            "name":    svc_name,
                            "version": version or "N/A",
                        })

            dev.open_ports    = sorted(ports)
            dev.services      = services
            dev.device_type   = self._guess_device_type(dev.vendor, dev.hostname, ports)
            dev.scan_complete = True
            self._notify(dev)

        except Exception as e:
            log.debug("Nmap deep scan error for %s: %s", ip, e)

    # ── Lookup Helpers ────────────────────────────────────────────────────────

    def _lookup_vendor(self, mac: str) -> str:
        """Look up vendor from MAC OUI (first 3 bytes)."""
        if not mac or mac == "00:00:00:00:00:00":
            return "Unknown"
        oui = mac[:8].upper()   # "AA:BB:CC"
        # Direct match
        if oui in OUI_MAP:
            return OUI_MAP[oui]
        # Partial match (first 6 chars)
        prefix = mac[:6].upper().replace(":", "")
        for key, vendor in OUI_MAP.items():
            if key.replace(":", "").upper().startswith(prefix[:4]):
                return vendor
        # Try macvendors API (online, with timeout)
        try:
            import urllib.request
            url = f"https://api.macvendors.com/{mac[:8]}"
            req = urllib.request.Request(url, headers={"User-Agent": "NetWatch-SOC/1.0"})
            with urllib.request.urlopen(req, timeout=3) as r:
                vendor = r.read().decode().strip()
                if vendor and "Not Found" not in vendor:
                    OUI_MAP[oui] = vendor   # Cache it
                    return vendor
        except Exception:
            pass
        return "Unknown Vendor"

    def _reverse_dns(self, ip: str) -> str:
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except Exception:
            return ip

    def _ttl_to_os(self, ttl: int) -> str:
        for (lo, hi), os_name in TTL_OS_MAP.items():
            if lo <= ttl <= hi:
                return os_name
        return "Unknown"

    def _parse_os_family(self, os_name: str) -> str:
        os_lower = os_name.lower()
        if "windows" in os_lower:          return "Windows"
        if "linux" in os_lower:            return "Linux"
        if "android" in os_lower:          return "Android"
        if "ios" in os_lower or "iphone" in os_lower or "ipad" in os_lower: return "iOS"
        if "macos" in os_lower or "mac os" in os_lower or "darwin" in os_lower: return "macOS"
        if "cisco" in os_lower or "ios xr" in os_lower: return "Cisco IOS"
        if "freebsd" in os_lower:          return "FreeBSD"
        if "ubuntu" in os_lower:           return "Ubuntu Linux"
        if "debian" in os_lower:           return "Debian Linux"
        if "centos" in os_lower or "rhel" in os_lower: return "Red Hat / CentOS"
        return os_name.split("(")[0].strip() if "(" in os_name else os_name

    def _guess_device_type(self, vendor: str, hostname: str, ports: list) -> str:
        v = vendor.lower()
        h = hostname.lower()

        if any(x in v for x in ["cisco", "juniper", "ubiquiti", "netgear", "d-link",
                                  "tp-link", "aruba", "fortinet", "mikrotik"]):
            return "Router / Network Device"
        if any(x in v for x in ["apple"]) and any(x in h for x in ["iphone", "ipad"]):
            return "iOS Device (iPhone/iPad)"
        if any(x in v for x in ["apple"]):
            return "Apple Mac / iOS"
        if any(x in v for x in ["samsung", "xiaomi", "huawei", "oneplus", "oppo", "vivo"]):
            return "Android Phone / Tablet"
        if any(x in v for x in ["raspberry"]):
            return "Raspberry Pi (Linux SBC)"
        if any(x in v for x in ["espressif"]):
            return "IoT Device (ESP32/ESP8266)"
        if any(x in v for x in ["amazon"]):
            return "Amazon Device (Echo/Fire)"
        if any(x in v for x in ["vmware", "virtualbox", "qemu"]):
            return "Virtual Machine"
        if any(x in v for x in ["intel", "realtek", "dell", "hp", "lenovo", "asus", "acer"]):
            return "PC / Laptop"
        if 3389 in ports:
            return "Windows PC (RDP enabled)"
        if 22 in ports and 80 not in ports and 443 not in ports:
            return "Linux Server"
        if 80 in ports or 443 in ports or 8080 in ports:
            return "Web Server"
        if 3306 in ports or 5432 in ports or 27017 in ports:
            return "Database Server"
        if any(x in h for x in ["router", "gateway", "ap-", "access"]):
            return "Router / Access Point"
        if any(x in h for x in ["android", "phone", "mobile"]):
            return "Android Device"
        if any(x in h for x in ["iphone", "ipad"]):
            return "iOS Device"
        if any(x in h for x in ["server", "srv", "db", "nas"]):
            return "Server"
        return "Unknown Device"

    def _dns_to_app(self, domain: str) -> Optional[str]:
        """Map a DNS query domain to an app name."""
        d = domain.lower().rstrip(".")
        for pattern, app in APP_DNS_PATTERNS.items():
            if pattern in d:
                return app
        return None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_or_create(self, ip: str, mac: str, ttl: int) -> DeviceDetail:
        with self._lock:
            if ip not in self._devices:
                self._devices[ip] = DeviceDetail(
                    ip=ip, mac=mac,
                    ttl_hint=self._ttl_to_os(ttl),
                    first_seen=time.time(),
                    last_seen=time.time()
                )
            return self._devices[ip]

    def _notify(self, dev: DeviceDetail):
        """Notify all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(dev)
            except Exception:
                pass

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple:
        try:
            return tuple(int(x) for x in ip.split("."))
        except Exception:
            return (0, 0, 0, 0)