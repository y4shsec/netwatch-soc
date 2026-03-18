"""
core/packet_sniffer.py — Live Packet Capture Engine
Thread-safe sniffer with callback system + PCAP export.
BUG FIXED: single __init__, no duplicate definition.
"""
import threading, time
from collections import deque
from typing import Callable, List, Optional

from scapy.all import sniff, wrpcap, conf
import config
from core.protocol_analyzer import ProtocolAnalyzer, PacketRecord
from utils.logger import get_logger

log = get_logger(__name__)


class PacketSniffer:

    def __init__(self, interface: str = config.INTERFACE):
        self.interface      = interface
        self.analyzer       = ProtocolAnalyzer()
        self._running       = False
        self._thread: Optional[threading.Thread] = None
        # Ring buffer of PacketRecord objects (for UI)
        self.packets: deque = deque(maxlen=config.PACKET_STORE_MAX)
        # Raw Scapy packets (for PCAP export only)
        self._raw: deque    = deque(maxlen=config.PACKET_STORE_MAX)
        self._callbacks: List[Callable[[PacketRecord], None]] = []
        self.total_captured = 0
        self.start_time: Optional[float] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def add_callback(self, fn: Callable[[PacketRecord], None]) -> None:
        """Register a function called with every captured PacketRecord."""
        if fn not in self._callbacks:
            self._callbacks.append(fn)

    def remove_callback(self, fn: Callable) -> None:
        if fn in self._callbacks:
            self._callbacks.remove(fn)

    def start(self) -> None:
        if self._running:
            log.warning("Sniffer already running on %s", self.interface)
            return
        self._running   = True
        self.start_time = time.time()
        self._thread    = threading.Thread(
            target=self._loop, name="PacketSnifferThread", daemon=True
        )
        self._thread.start()
        log.info("Sniffer started on interface: %s", self.interface)

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log.info("Sniffer stopped. Total captured: %d", self.total_captured)

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        elapsed = time.time() - (self.start_time or time.time())
        return {
            "total_captured": self.total_captured,
            "elapsed_seconds": round(elapsed, 1),
            "pps": round(self.total_captured / max(elapsed, 1), 1),
            "interface": self.interface,
            "running": self._running,
        }

    def export_pcap(self, filepath: str) -> bool:
        try:
            wrpcap(filepath, list(self._raw))
            log.info("PCAP exported to %s (%d packets)", filepath, len(self._raw))
            return True
        except Exception as e:
            log.error("PCAP export error: %s", e)
            return False

    # ── Internal ──────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        try:
            sniff(
                iface=self.interface,
                prn=self._process,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            log.error("Permission denied on %s — run as sudo/administrator.", self.interface)
            self._running = False
        except Exception as e:
            log.error("Sniffer error: %s", e)
            self._running = False

    def _process(self, raw_pkt) -> None:
        try:
            record = self.analyzer.analyze(raw_pkt)
            self.packets.appendleft(record)
            self._raw.appendleft(raw_pkt)
            self.total_captured += 1
            for cb in list(self._callbacks):
                try:
                    cb(record)
                except Exception as e:
                    log.debug("Callback error: %s", e)
        except Exception as e:
            log.debug("Packet processing error: %s", e)
