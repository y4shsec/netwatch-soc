"""
detection/port_scan_detector.py
Detects port scans by counting unique dst ports per source IP in a sliding window.
FIXED: constructor accepts threshold and window for flexible testing.
"""
import time
from collections import defaultdict
from typing import Dict, Set
import config
from utils.alert_manager import push_alert
from utils.logger import get_logger
log = get_logger(__name__)


class PortScanDetector:
    def __init__(
        self,
        threshold: int = config.PORT_SCAN_THRESHOLD,
        window: int    = config.PORT_SCAN_WINDOW_SEC,
    ):
        self.threshold = threshold
        self.window    = window
        self._data: Dict[str, list] = defaultdict(list)
        log.info("Port scan detector: threshold=%d ports in %ds", threshold, window)

    def check(self, record) -> bool:
        """Returns True if a port scan was detected."""
        if record.protocol != "TCP":
            return False
        # SYN only (no ACK) = typical scanner packet
        if "S" not in record.tcp_flags or "A" in record.tcp_flags:
            return False

        src, dport, now = record.src_ip, record.dst_port, time.time()
        self._data[src].append((now, dport))

        # Drop old entries outside the window
        cutoff = now - self.window
        self._data[src] = [(t, p) for t, p in self._data[src] if t >= cutoff]

        unique: Set[int] = {p for _, p in self._data[src]}
        if len(unique) >= self.threshold:
            push_alert(
                severity   = "HIGH",
                alert_type = "PORT_SCAN",
                src_ip     = src,
                message    = (
                    f"Port scan from {src} — "
                    f"{len(unique)} ports in {self.window}s"
                ),
                details    = {
                    "port_count":  len(unique),
                    "sample_ports": sorted(unique)[:10],
                    "window_sec":  self.window,
                },
            )
            self._data[src] = []   # reset after alert
            return True
        return False