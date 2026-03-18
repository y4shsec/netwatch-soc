"""
integrations/pcap_handler.py — PCAP Import / Export
"""
import os, time
from typing import List
from scapy.all import rdpcap, wrpcap
from collections import Counter
import config
from core.protocol_analyzer import ProtocolAnalyzer, PacketRecord
from utils.logger import get_logger

log = get_logger(__name__)
os.makedirs(config.PCAP_EXPORT_DIR, exist_ok=True)


class PCAPHandler:
    def __init__(self):
        self.analyzer = ProtocolAnalyzer()

    def export(self, raw_packets: list, filename: str = None) -> str:
        fn   = filename or f"capture_{int(time.time())}.pcap"
        path = os.path.join(config.PCAP_EXPORT_DIR, fn)
        try:
            wrpcap(path, raw_packets)
            log.info("Exported %d packets → %s", len(raw_packets), path)
            return path
        except Exception as e:
            log.error("PCAP export: %s", e)
            return ""

    def import_pcap(self, filepath: str) -> List[PacketRecord]:
        if not os.path.exists(filepath):
            log.error("File not found: %s", filepath)
            return []
        try:
            pkts = rdpcap(filepath)
            records = []
            for p in pkts:
                try:
                    records.append(self.analyzer.analyze(p))
                except Exception:
                    pass
            log.info("Loaded %d packets from %s", len(records), filepath)
            return records
        except Exception as e:
            log.error("PCAP import: %s", e)
            return []

    def analyze_pcap(self, filepath: str) -> dict:
        records = self.import_pcap(filepath)
        if not records:
            return {"error": "No packets loaded"}
        pc, sc, dc, dp = Counter(), Counter(), Counter(), Counter()
        for r in records:
            pc[r.protocol] += 1
            if r.src_ip != "N/A": sc[r.src_ip] += 1
            if r.dst_ip != "N/A": dc[r.dst_ip] += 1
            if r.dst_port:        dp[r.dst_port] += 1
        return {
            "total_packets": len(records),
            "protocols":     dict(pc.most_common(10)),
            "top_src_ips":   dict(sc.most_common(10)),
            "top_dst_ips":   dict(dc.most_common(10)),
            "top_dst_ports": dict(dp.most_common(10)),
            "duration_sec":  round(records[-1].timestamp - records[0].timestamp, 2) if len(records)>1 else 0,
        }
