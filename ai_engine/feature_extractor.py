"""
ai_engine/feature_extractor.py
Converts PacketRecord → numerical feature vector for ML models.
Also maps CIC-IDS-2017 CSV columns to our feature set.
"""
from typing import List
from core.protocol_analyzer import PacketRecord

PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1, "ARP": 0, "OTHER": 0}

FEATURE_NAMES = [
    "packet_size", "payload_length", "src_port", "dst_port",
    "protocol_num", "flag_syn", "flag_ack", "flag_fin", "flag_rst",
    "is_dns", "is_http", "is_ssh", "is_ftp",
    "flow_pkt_count", "flow_bytes", "flow_pps", "flow_bps",
]

# CIC-IDS-2017 CSV columns we use (strip spaces from names in pandas)
CICIDS_COLS = [
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Source Port",
    "Destination Port",
    "Protocol",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Total Fwd Packets",
    "Total Backward Packets",
]
CICIDS_LABEL = "Label"


def extract_features(record: PacketRecord, flow_stats: dict = None) -> List[float]:
    flags = record.tcp_flags or ""
    app   = record.app_protocol or ""
    fs    = flow_stats or {}
    return [
        float(record.packet_size),
        float(record.payload_length),
        float(min(record.src_port, 65535)),
        float(min(record.dst_port, 65535)),
        float(PROTO_MAP.get(record.protocol, 0)),
        1.0 if "S" in flags else 0.0,
        1.0 if "A" in flags else 0.0,
        1.0 if "F" in flags else 0.0,
        1.0 if "R" in flags else 0.0,
        1.0 if app == "DNS"  else 0.0,
        1.0 if app == "HTTP" else 0.0,
        1.0 if record.dst_port == 22 else 0.0,
        1.0 if record.dst_port == 21 else 0.0,
        float(fs.get("pkt_count", 1)),
        float(fs.get("bytes",     record.packet_size)),
        float(fs.get("pps",       0.0)),
        float(fs.get("bps",       0.0)),
    ]


def map_label(raw: str) -> str:
    """Normalise CIC-IDS-2017 label to 5-class scheme."""
    s = raw.strip().upper()
    if s in ("BENIGN", "NORMAL"):                          return "NORMAL"
    if "DDOS" in s or "DOS" in s:                          return "DDOS"
    if "PORT_SCAN" in s or "PORTSCAN" in s or "PORT SCAN" in s: return "PORT_SCAN"
    if "BRUTE_FORCE" in s or "BRUTE" in s or "PATATOR" in s:   return "BRUTE_FORCE"
    if "MALWARE_C2" in s or "BOT" in s or "INFILTRATION" in s or "HEART" in s: return "MALWARE_C2"
    return "OTHER"