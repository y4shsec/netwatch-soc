"""
core/protocol_analyzer.py — Deep Protocol Dissector
Converts raw Scapy packets into structured PacketRecord objects.
"""
import time
from dataclasses import dataclass, field, asdict
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
import config

@dataclass
class PacketRecord:
    timestamp:       float = field(default_factory=time.time)
    src_ip:          str   = "N/A"
    dst_ip:          str   = "N/A"
    src_mac:         str   = "N/A"
    dst_mac:         str   = "N/A"
    protocol:        str   = "OTHER"
    app_protocol:    str   = ""
    src_port:        int   = 0
    dst_port:        int   = 0
    packet_size:     int   = 0
    payload_length:  int   = 0
    ttl:             int   = 0
    tcp_flags:       str   = ""
    icmp_type:       int   = -1
    arp_op:          str   = ""
    dns_query:       str   = ""
    dns_response:    str   = ""
    http_method:     str   = ""
    http_host:       str   = ""
    http_path:       str   = ""
    info:            str   = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ProtocolAnalyzer:
    FLAG_CHARS = {0x01:"F", 0x02:"S", 0x04:"R", 0x08:"P", 0x10:"A", 0x20:"U"}

    def analyze(self, packet) -> PacketRecord:
        rec = PacketRecord()
        rec.packet_size = len(packet)
        self._layer2(packet, rec)
        self._layer3(packet, rec)
        self._layer4(packet, rec)
        self._layer7(packet, rec)
        self._info(rec)
        return rec

    def _layer2(self, pkt, rec):
        if Ether in pkt:
            rec.src_mac = pkt[Ether].src.upper()
            rec.dst_mac = pkt[Ether].dst.upper()

    def _layer3(self, pkt, rec):
        if IP in pkt:
            rec.src_ip = pkt[IP].src
            rec.dst_ip = pkt[IP].dst
            rec.ttl    = pkt[IP].ttl
        elif IPv6 in pkt:
            rec.src_ip = pkt[IPv6].src
            rec.dst_ip = pkt[IPv6].dst
            rec.ttl    = pkt[IPv6].hlim
        elif ARP in pkt:
            rec.protocol = "ARP"
            rec.src_ip   = pkt[ARP].psrc
            rec.dst_ip   = pkt[ARP].pdst
            rec.src_mac  = pkt[ARP].hwsrc.upper()
            rec.arp_op   = "who-has" if pkt[ARP].op == 1 else "is-at"

    def _layer4(self, pkt, rec):
        if TCP in pkt:
            rec.protocol       = "TCP"
            rec.src_port       = pkt[TCP].sport
            rec.dst_port       = pkt[TCP].dport
            rec.tcp_flags      = self._flags(int(pkt[TCP].flags))
            rec.payload_length = len(bytes(pkt[TCP].payload))
            p = config.PROTOCOL_PORTS.get(rec.dst_port) or config.PROTOCOL_PORTS.get(rec.src_port)
            if p: rec.app_protocol = p
        elif UDP in pkt:
            rec.protocol       = "UDP"
            rec.src_port       = pkt[UDP].sport
            rec.dst_port       = pkt[UDP].dport
            rec.payload_length = len(bytes(pkt[UDP].payload))
            p = config.PROTOCOL_PORTS.get(rec.dst_port) or config.PROTOCOL_PORTS.get(rec.src_port)
            if p: rec.app_protocol = p
        elif ICMP in pkt:
            rec.protocol  = "ICMP"
            rec.icmp_type = pkt[ICMP].type

    def _layer7(self, pkt, rec):
        if DNS in pkt:
            rec.app_protocol = "DNS"
            try:
                if pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0:
                    rec.dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
                elif pkt[DNS].qr == 1 and pkt[DNS].ancount > 0:
                    rdata = pkt[DNS].an.rdata
                    rec.dns_response = str(rdata) if rdata else ""
            except Exception:
                pass
        if Raw in pkt:
            raw = bytes(pkt[Raw].load)
            if raw[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD"):
                rec.app_protocol = "HTTP"
                try:
                    lines = raw.decode("utf-8", errors="replace").split("\r\n")
                    parts = lines[0].split(" ")
                    rec.http_method = parts[0]
                    rec.http_path   = parts[1] if len(parts) > 1 else ""
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            rec.http_host = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass

    def _flags(self, f: int) -> str:
        return "".join(c for b, c in self.FLAG_CHARS.items() if f & b)

    def _info(self, rec):
        if rec.protocol == "ARP":
            rec.info = f"ARP {rec.arp_op} {rec.dst_ip} tell {rec.src_ip}"
        elif rec.protocol == "ICMP":
            m = {0:"Echo Reply", 8:"Echo Request", 3:"Dest Unreachable", 11:"TTL Exceeded"}
            rec.info = m.get(rec.icmp_type, f"ICMP type={rec.icmp_type}")
        elif rec.app_protocol == "DNS":
            rec.info = f"DNS Query {rec.dns_query}" if rec.dns_query else f"DNS Response {rec.dns_response}"
        elif rec.app_protocol == "HTTP":
            rec.info = f"{rec.http_method} {rec.http_host}{rec.http_path}"
        elif rec.protocol in ("TCP", "UDP"):
            fl = f" [{rec.tcp_flags}]" if rec.tcp_flags else ""
            rec.info = f"{rec.src_ip}:{rec.src_port} → {rec.dst_ip}:{rec.dst_port}{fl}"
        else:
            rec.info = rec.protocol or "Unknown"
