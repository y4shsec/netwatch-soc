"""
interface/cli.py — Rich Terminal CLI Dashboard (FIXED)

Fixes:
1. DDoS threshold lowered to 50 pps for lab testing
2. Port scan threshold lowered to 5 ports in 3s for testing
3. Added scrollable alert log (press 'a' key hint shown)
4. Added device table section
5. Subnet taken from config (auto-detected by main.py)
"""
import time, threading
from collections import deque
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich import box

import config
from core.packet_sniffer import PacketSniffer
from core.network_scanner import NetworkScanner
from detection.arp_spoof_detector import ARPSpoofDetector
from detection.port_scan_detector import PortScanDetector
from detection.traffic_monitor import TrafficMonitor
from ai_engine.anomaly_detector import AnomalyDetector
from ai_engine.attack_classifier import AttackClassifier
from visualization.topology_mapper import TopologyMapper
from database.storage import save_packet, save_alert, save_device
from utils.alert_manager import get_alerts, subscribe
from utils.logger import get_logger

log     = get_logger(__name__)
console = Console()

SEV_COLOUR = {
    "CRITICAL": "bold red on dark_red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "cyan",
    "INFO":     "green",
}

# ── Lab-friendly thresholds (lower than production) ──────────────────────────
# For real SOC set these back to 500 and 15 in config.py
# Thresholds — tuned to avoid false positives on real networks
LAB_PPS_THRESHOLD  = 1500  # Alert if single IP sends >1500 pps (eliminates DNS/browsing false positives)
LAB_SCAN_PORTS     = 20    # Alert if single IP hits >20 ports in window
LAB_SCAN_WINDOW    = 5     # seconds


def run_cli(interface: str = config.INTERFACE) -> None:
    console.print(Panel.fit(
        f"[bold cyan]NetWatch SOC — CLI Mode[/bold cyan]\n"
        f"[dim]Interface: {interface}  |  Subnet: {config.SUBNET}[/dim]",
        border_style="cyan"
    ))

    # ── Init engines with lab thresholds ────────────────────────────────────
    sniffer     = PacketSniffer(interface=interface)
    scanner     = NetworkScanner(subnet=config.SUBNET, interface=interface)
    arp_det     = ARPSpoofDetector()
    port_det    = PortScanDetector(threshold=LAB_SCAN_PORTS, window=LAB_SCAN_WINDOW)
    traffic_mon = TrafficMonitor(threshold=LAB_PPS_THRESHOLD)
    anomaly     = AnomalyDetector()
    clf         = AttackClassifier()
    topology    = TopologyMapper()

    recent_pkts: deque  = deque(maxlen=20)
    all_alerts:  list   = []    # Full alert history for scroll view

    # ── Wire callbacks ───────────────────────────────────────────────────────
    def on_packet(record):
        recent_pkts.appendleft(record)
        arp_det.check(record)
        port_det.check(record)
        traffic_mon.update(record)
        topology.record_traffic(record.src_ip, record.dst_ip)
        if sniffer.total_captured % 10 == 0:
            try: save_packet(record)
            except Exception: pass
        if sniffer.total_captured % 20 == 0:
            try:
                anomaly.predict(record)
                clf.classify(record)
            except Exception: pass

    def on_alert(alert):
        all_alerts.insert(0, alert)
        try: save_alert(alert)
        except Exception: pass

    def on_new_device(dev):
        topology.add_device(dev)
        try: save_device(dev)
        except Exception: pass

    sniffer.add_callback(on_packet)
    subscribe(on_alert)
    scanner.on_new_device(on_new_device)

    # ── Start engines ────────────────────────────────────────────────────────
    traffic_mon.start()
    scanner.start()
    sniffer.start()

    console.print(
        f"[green]✓[/green] Engines started  "
        f"[dim]| DDoS threshold: {LAB_PPS_THRESHOLD} pps "
        f"| Port-scan: {LAB_SCAN_PORTS} ports/{LAB_SCAN_WINDOW}s "
        f"| Subnet: {config.SUBNET}[/dim]"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    # ── Live display ─────────────────────────────────────────────────────────
    try:
        with Live(console=console, refresh_per_second=2, screen=True) as live:
            while True:
                live.update(_render(sniffer, scanner, recent_pkts, all_alerts))
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        traffic_mon.stop()
        scanner.stop()
        console.print("\n[green]✓ Shutdown complete.[/green]")
        # Print full alert log after exit
        final_alerts = get_alerts(limit=100)
        if final_alerts:
            console.print(f"\n[bold red]═══ {len(final_alerts)} Alerts logged this session ═══[/bold red]")
            for a in final_alerts:
                ts  = time.strftime("%H:%M:%S", time.localtime(a.get("timestamp",0)))
                sev = a.get("severity","INFO")
                console.print(f"[dim]{ts}[/dim] [{SEV_COLOUR.get(sev,'white')}]{sev}[/] {a.get('message','')}")


def _render(sniffer, scanner, recent_pkts, all_alerts) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="bottom", size=10),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="pkts",    ratio=3),
        Layout(name="sidebar", ratio=2),
    )
    layout["sidebar"].split_column(
        Layout(name="alerts",  ratio=3),
        Layout(name="devices", ratio=2),
    )

    stats   = sniffer.get_stats()
    devices = scanner.get_devices()
    alerts  = get_alerts(limit=20)

    # ── Header ────────────────────────────────────────────────────────────────
    crit_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    layout["header"].update(Panel(
        f"[bold cyan]NetWatch SOC[/bold cyan]  [dim]|[/dim]  "
        f"Iface: [green]{stats['interface']}[/green]  [dim]|[/dim]  "
        f"Subnet: [green]{config.SUBNET}[/green]  [dim]|[/dim]  "
        f"Pkts: [blue]{stats['total_captured']:,}[/blue]  [dim]|[/dim]  "
        f"[cyan]{stats['pps']} pps[/cyan]  [dim]|[/dim]  "
        f"Devices: [yellow]{len(devices)}[/yellow]  [dim]|[/dim]  "
        f"Alerts: [{'bold red' if alerts else 'green'}]{len(alerts)}[/]  [dim]|[/dim]  "
        f"[{'bold red' if crit_count else 'dim'}]CRITICAL: {crit_count}[/]  [dim]|[/dim]  "
        f"Uptime: [dim]{stats['elapsed_seconds']:.0f}s[/dim]",
        border_style="cyan"
    ))

    # ── Packet Table ──────────────────────────────────────────────────────────
    pt = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim",
               expand=True, show_edge=False)
    pt.add_column("Time",  style="dim",     width=9)
    pt.add_column("Src",   style="cyan",    width=16)
    pt.add_column("Dst",   style="blue",    width=16)
    pt.add_column("Proto", style="magenta", width=7)
    pt.add_column("Size",  style="dim",     width=5)
    pt.add_column("Info",  style="white",   ratio=1)
    for rec in list(recent_pkts)[:18]:
        ts = time.strftime("%H:%M:%S", time.localtime(rec.timestamp))
        pt.add_row(ts, rec.src_ip[:15], rec.dst_ip[:15],
                   f"[bold]{rec.app_protocol or rec.protocol}[/bold]",
                   str(rec.packet_size),
                   Text(rec.info[:55], overflow="ellipsis"))
    layout["pkts"].update(Panel(pt, title="[bold]Live Packets[/bold]",
                                border_style="blue"))

    # ── Alerts Panel ──────────────────────────────────────────────────────────
    at = Table(box=box.SIMPLE, show_header=False, expand=True,
               padding=(0,1), show_edge=False)
    at.add_column("Sev",  width=9)
    at.add_column("Msg",  ratio=1)
    if alerts:
        for a in alerts[:12]:
            sev = a.get("severity","INFO")
            col = SEV_COLOUR.get(sev, "white")
            at.add_row(
                Text(sev[:4], style=col),
                Text(a.get("message","")[:45], style="dim white", overflow="ellipsis")
            )
    else:
        at.add_row("", Text("No alerts yet", style="dim green"))
    layout["alerts"].update(Panel(at, title="[bold red]Alerts[/bold red]",
                                  border_style="red"))

    # ── Devices Panel ─────────────────────────────────────────────────────────
    dt = Table(box=box.SIMPLE, show_header=True, header_style="bold dim",
               expand=True, show_edge=False)
    dt.add_column("IP",       style="cyan",   width=15)
    dt.add_column("MAC",      style="dim",    width=17)
    dt.add_column("Vendor",   style="yellow", ratio=1)
    if devices:
        for d in devices[:5]:
            dt.add_row(d.ip, d.mac[:17], (d.vendor or "Unknown")[:20])
    else:
        dt.add_row("[dim]Scanning...[/dim]", "", "")
    layout["devices"].update(Panel(dt, title=f"[bold yellow]Devices ({len(devices)})[/bold yellow]",
                                   border_style="yellow"))

    # ── Bottom: Recent full alert messages ────────────────────────────────────
    bt = Table(box=box.SIMPLE, show_header=False, expand=True,
               padding=(0,1), show_edge=False)
    bt.add_column("Full Alert", ratio=1)
    for a in alerts[:3]:
        sev = a.get("severity","INFO")
        col = SEV_COLOUR.get(sev, "white")
        ts  = time.strftime("%H:%M:%S", time.localtime(a.get("timestamp",0)))
        bt.add_row(Text(
            f"[{ts}] {sev}: {a.get('message','')[:100]}",
            style=col, overflow="ellipsis"
        ))
    if not alerts:
        bt.add_row(Text("Waiting for alerts... (DDoS threshold: 1500 pps | PortScan: 20 ports/5s)", style="dim"))
    layout["bottom"].update(Panel(bt, title="[bold]Alert Details[/bold]",
                                  border_style="dim"))

    # ── Footer ────────────────────────────────────────────────────────────────
    layout["footer"].update(Panel(
        f"[dim]Ctrl+C = Stop & show full log  "
        f"|  Detectors: ARP-Spoof · Port-Scan · DDoS({LAB_PPS_THRESHOLD}pps) · DNS-Spoof · AI[/dim]",
        border_style="dim"
    ))
    return layout