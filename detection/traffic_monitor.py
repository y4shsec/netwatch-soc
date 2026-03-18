"""
detection/traffic_monitor.py
Per-IP packet rate monitor. Alerts on DDoS floods and DNS spoofing.
FIXED: accepts threshold in constructor so CLI/tests can use lower values.
"""
import time, threading
from collections import defaultdict
from typing import Dict
import config
from utils.alert_manager import push_alert
from utils.logger import get_logger
log = get_logger(__name__)


class TrafficMonitor:
    def __init__(self, threshold: int = config.ALERT_PPS_THRESHOLD):
        self.threshold    = threshold
        self._counters: Dict[str, int] = defaultdict(int)
        self._lock        = threading.Lock()
        self._alerted: Dict[str, float] = {}
        self._alert_cooldown = 15      # seconds before re-alerting same IP
        self._dns_table: Dict[str, set] = defaultdict(set)
        self._running     = False
        self._thread      = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, name="TrafficMonitor", daemon=True
        )
        self._thread.start()
        log.info("Traffic monitor started (DDoS threshold: %d pps)", self.threshold)

    def stop(self) -> None:
        self._running = False

    def update(self, record) -> None:
        """Call this for every captured PacketRecord."""
        with self._lock:
            self._counters[record.src_ip] += 1
        # DNS spoof check
        if record.app_protocol == "DNS" and record.dns_query and record.dns_response:
            self._check_dns(record)

    def _loop(self) -> None:
        while self._running:
            time.sleep(1.0)
            with self._lock:
                snap = dict(self._counters)
                self._counters = defaultdict(int)
            now = time.time()
            for ip, count in snap.items():
                if count >= self.threshold:
                    last = self._alerted.get(ip, 0)
                    if now - last >= self._alert_cooldown:
                        self._alerted[ip] = now
                        push_alert(
                            severity   = "HIGH",
                            alert_type = "DDOS_FLOOD",
                            src_ip     = ip,
                            message    = (
                                f"DDoS/Flood from {ip}: "
                                f"{count} pkt/s (threshold: {self.threshold})"
                            ),
                            details    = {"pps": count, "threshold": self.threshold},
                        )

    def _check_dns(self, record) -> None:
        domain  = record.dns_query
        resp_ip = str(record.dns_response)
        known   = self._dns_table[domain]
        if known and resp_ip not in known:
            push_alert(
                severity   = "MEDIUM",
                alert_type = "DNS_SPOOF",
                src_ip     = record.src_ip,
                message    = (
                    f"DNS Spoof? {domain} → {resp_ip} "
                    f"(previously: {list(known)[:2]})"
                ),
                details    = {"domain": domain, "new_ip": resp_ip, "known": list(known)},
            )
        self._dns_table[domain].add(resp_ip)