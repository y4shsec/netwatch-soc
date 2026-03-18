"""
detection/arp_spoof_detector.py
Detects ARP spoofing by tracking IP→MAC consistency.
"""
from typing import Dict
from utils.alert_manager import push_alert
from utils.logger import get_logger
log = get_logger(__name__)


class ARPSpoofDetector:
    def __init__(self):
        self._table: Dict[str, str] = {}

    def check(self, record) -> bool:
        if record.protocol != "ARP" or record.arp_op != "is-at":
            return False
        ip, mac = record.src_ip, record.src_mac
        if not ip or not mac:
            return False
        known = self._table.get(ip)
        if known is None:
            self._table[ip] = mac
            return False
        if known != mac:
            push_alert(
                severity="CRITICAL", alert_type="ARP_SPOOF", src_ip=ip,
                message=f"ARP Spoofing! IP {ip} — was {known}, now {mac}",
                details={"ip": ip, "original_mac": known, "attacker_mac": mac},
            )
            log.warning("ARP SPOOF: %s  %s → %s", ip, known, mac)
            return True
        return False

    def get_table(self) -> Dict[str, str]:
        return dict(self._table)
