"""
interface/gui.py — Tkinter Desktop GUI
FIXED:
1. Passes correct interface + subnet to NetworkScanner at init time
2. TrafficMonitor threshold: 1500 pps (no false positives)
3. Added Stop button to halt all scanning
4. Packet stream confirmed working — added debug counter in title bar
5. Packets now insert correctly into treeview
"""
import time, threading, queue, os, json
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

import config
from core.packet_sniffer import PacketSniffer
from core.network_scanner import NetworkScanner
from detection.arp_spoof_detector import ARPSpoofDetector
from detection.port_scan_detector import PortScanDetector
from detection.traffic_monitor import TrafficMonitor
from ai_engine.anomaly_detector import AnomalyDetector
from ai_engine.attack_classifier import AttackClassifier
from visualization.topology_mapper import TopologyMapper
from integrations.pcap_handler import PCAPHandler
from database.storage import save_packet, save_alert, save_device
from utils.alert_manager import get_alerts, subscribe
from utils.logger import get_logger

log = get_logger(__name__)

BG    = "#0d1117"
BG2   = "#161b22"
FG    = "#c9d1d9"
ACCENT= "#58a6ff"
GREEN = "#3fb950"
RED   = "#f85149"
YELLOW= "#d29922"

# Lab-friendly thresholds
LAB_PPS  = 1500   # pps per source IP before DDoS alert
LAB_PORTS= 20     # unique ports in window before port scan alert
LAB_WIN  = 5      # seconds for port scan window


class NetWatchGUI:

    def __init__(self, root: tk.Tk, interface: str = config.INTERFACE):
        self.root      = root
        self.interface = interface

        # ── All instance vars initialised here ────────────────────────────────
        self._pkt_count   = 0
        self._pkt_queue:   queue.Queue = queue.Queue(maxsize=2000)
        self._alert_queue: queue.Queue = queue.Queue(maxsize=500)
        self._ai_queue:    queue.Queue = queue.Queue(maxsize=200)
        self._running      = False

        # ── Backend engines — pass interface + subnet explicitly ──────────────
        self.sniffer     = PacketSniffer(interface=interface)
        # Scanner gets interface AND subnet from config (patched by main.py)
        self.scanner     = NetworkScanner(
            subnet    = config.SUBNET,
            interface = interface,
        )
        self.arp_det     = ARPSpoofDetector()
        self.port_det    = PortScanDetector(threshold=LAB_PORTS, window=LAB_WIN)
        self.traffic_mon = TrafficMonitor(threshold=LAB_PPS)
        self.anomaly     = AnomalyDetector()
        self.clf         = AttackClassifier()
        self.topology    = TopologyMapper()
        self.pcap        = PCAPHandler()

        self._setup_window()
        self._build_ui()
        self._wire_and_start()
        self._schedule_refresh()

    # ── Window ────────────────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title(f"NetWatch SOC — Network Security Monitor")
        self.root.geometry("1300x820")
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Top bar
        top = tk.Frame(self.root, bg=BG2, height=50)
        top.pack(fill="x", side="top")
        tk.Label(top, text="⬡ NetWatch SOC", font=("Courier New",15,"bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=14, pady=10)

        self._status_var = tk.StringVar(value="● Starting…")
        tk.Label(top, textvariable=self._status_var,
                 font=("Courier New",11), bg=BG2, fg=YELLOW).pack(side="left", padx=8)

        # STOP button
        self._stop_btn = tk.Button(
            top, text="  ⏹ STOP  ",
            command=self._stop_all,
            bg=RED, fg="#fff",
            font=("Courier New",10,"bold"),
            relief="flat", cursor="hand2", state="disabled"
        )
        self._stop_btn.pack(side="left", padx=8)

        self._stats_var = tk.StringVar(value="")
        tk.Label(top, textvariable=self._stats_var,
                 font=("Courier New",10), bg=BG2, fg=FG).pack(side="right", padx=14)

        # Notebook
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",     background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=FG,
                        padding=[12,6], font=("Courier New",10))
        style.map("TNotebook.Tab",
                  background=[("selected",BG)],
                  foreground=[("selected",ACCENT)])

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=4, pady=4)
        self._nb = nb   # save reference for navigation

        self._build_home_tab(nb)
        self._build_packets_tab(nb)
        self._build_devices_tab(nb)
        self._build_alerts_tab(nb)
        self._build_ai_tab(nb)
        self._build_pcap_tab(nb)

    def _make_tree(self, parent, cols, hdrs):
        style = ttk.Style()
        style.configure("Dark.Treeview",
            background=BG2, foreground=FG, rowheight=22,
            fieldbackground=BG2, font=("Courier New",9))
        style.configure("Dark.Treeview.Heading",
            background=BG, foreground=ACCENT,
            font=("Courier New",9,"bold"))
        style.map("Dark.Treeview",
                  background=[("selected","#1f6feb")])

        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            style="Dark.Treeview",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set
        )
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        for col, hdr in zip(cols, hdrs):
            tree.heading(col, text=hdr)
            tree.column(col, width=120, anchor="w")
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both",  expand=True)
        return tree

    def _build_home_tab(self, nb):
        """Home / Overview tab — always visible, acts as dashboard home."""
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=" 🏠 Home ")

        # Title
        tk.Label(frame, text="NetWatch SOC — Overview",
                 font=("Courier New",14,"bold"), bg=BG, fg=ACCENT
                 ).pack(pady=(20,4))
        tk.Label(frame, text=f"Interface: {self.interface}  |  Subnet: {config.SUBNET}",
                 font=("Courier New",10), bg=BG, fg=YELLOW
                 ).pack(pady=(0,20))

        # Quick-nav buttons
        nav_frame = tk.Frame(frame, bg=BG)
        nav_frame.pack(pady=10)

        btn_style = dict(font=("Courier New",11,"bold"), relief="flat",
                         cursor="hand2", width=22, pady=10)

        tk.Button(nav_frame, text="📡  Live Packets",
                  bg="#1f6feb", fg="#fff",
                  command=lambda: self._nb.select(1),
                  **btn_style).grid(row=0, column=0, padx=8, pady=6)

        tk.Button(nav_frame, text="🖥   Connected Devices",
                  bg="#238636", fg="#fff",
                  command=lambda: self._nb.select(2),
                  **btn_style).grid(row=0, column=1, padx=8, pady=6)

        tk.Button(nav_frame, text="🚨  Security Alerts",
                  bg="#da3633", fg="#fff",
                  command=lambda: self._nb.select(3),
                  **btn_style).grid(row=1, column=0, padx=8, pady=6)

        tk.Button(nav_frame, text="🤖  AI Detection",
                  bg="#6e40c9", fg="#fff",
                  command=lambda: self._nb.select(4),
                  **btn_style).grid(row=1, column=1, padx=8, pady=6)

        tk.Button(nav_frame, text="📂  PCAP Analyzer",
                  bg="#21262d", fg=FG,
                  command=lambda: self._nb.select(5),
                  **btn_style).grid(row=2, column=0, padx=8, pady=6)

        tk.Button(nav_frame, text="🔍  Scan Devices Now",
                  bg=ACCENT, fg="#000",
                  command=self._do_scan,
                  **btn_style).grid(row=2, column=1, padx=8, pady=6)

        # Live stats section
        stats_frame = tk.Frame(frame, bg=BG2, relief="flat")
        stats_frame.pack(fill="x", padx=40, pady=20)

        tk.Label(stats_frame, text="Live Stats",
                 font=("Courier New",10,"bold"), bg=BG2, fg=ACCENT
                 ).pack(pady=(10,6))

        self._home_stats_var = tk.StringVar(value="Starting engines...")
        tk.Label(stats_frame, textvariable=self._home_stats_var,
                 font=("Courier New",10), bg=BG2, fg=FG, justify="center"
                 ).pack(pady=(0,10))

    def _build_packets_tab(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=" 📡 Live Packets ")

        # Nav bar
        nav = tk.Frame(frame, bg=BG); nav.pack(fill="x", padx=6, pady=4)
        tk.Button(nav, text="← Home", command=lambda: self._nb.select(0),
                  bg=BG2, fg=ACCENT, font=("Courier New",9), relief="flat",
                  cursor="hand2").pack(side="left", padx=2)
        # Counter label at top
        self._pkt_label_var = tk.StringVar(value="0 packets captured")
        tk.Label(nav, textvariable=self._pkt_label_var,
                 bg=BG, fg=ACCENT,
                 font=("Courier New",10)).pack(side="left", padx=10)

        cols = ["time","src_ip","dst_ip","proto","app","size","info"]
        hdrs = ["Time","Src IP","Dst IP","Proto","App","Size","Info"]
        self._pkt_tree = self._make_tree(frame, cols, hdrs)
        self._pkt_tree.column("time",   width=75)
        self._pkt_tree.column("src_ip", width=130)
        self._pkt_tree.column("dst_ip", width=130)
        self._pkt_tree.column("proto",  width=60)
        self._pkt_tree.column("app",    width=70)
        self._pkt_tree.column("size",   width=55)
        self._pkt_tree.column("info",   width=380)
        for tag, col in [
            ("TCP",ACCENT),("UDP",GREEN),("DNS",YELLOW),
            ("ARP","#a78bfa"),("ICMP",RED),("OTHER",FG)
        ]:
            self._pkt_tree.tag_configure(tag, foreground=col)

    def _build_devices_tab(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=" 🖥  Devices ")
        bf = tk.Frame(frame, bg=BG)
        bf.pack(fill="x", padx=8, pady=6)

        tk.Button(bf, text="← Home", command=lambda: self._nb.select(0),
                  bg=BG2, fg=ACCENT, font=("Courier New",9), relief="flat",
                  cursor="hand2").pack(side="left", padx=2)

        tk.Label(bf, text=f"Subnet: {config.SUBNET}  |  Interface: {self.interface}",
                 bg=BG, fg=YELLOW,
                 font=("Courier New",10)).pack(side="left", padx=6)

        tk.Button(bf, text="  🔍 Scan Now  ", command=self._do_scan,
                  bg=ACCENT, fg="#000",
                  font=("Courier New",10,"bold"),
                  relief="flat", cursor="hand2").pack(side="right", padx=4)

        self._dev_count_var = tk.StringVar(value="0 devices found")
        tk.Label(bf, textvariable=self._dev_count_var,
                 bg=BG, fg=GREEN,
                 font=("Courier New",10)).pack(side="right", padx=10)

        self._dev_tree = self._make_tree(
            frame,
            ["ip","mac","hostname","vendor","last_seen"],
            ["IP Address","MAC","Hostname","Vendor","Last Seen"]
        )

    def _build_alerts_tab(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=" 🚨 Alerts ")

        bf = tk.Frame(frame, bg=BG)
        bf.pack(fill="x", padx=8, pady=4)
        tk.Button(bf, text="← Home", command=lambda: self._nb.select(0),
                  bg=BG2, fg=ACCENT, font=("Courier New",9), relief="flat",
                  cursor="hand2").pack(side="left", padx=2)
        self._alert_count_var = tk.StringVar(value="0 alerts")
        tk.Label(bf, textvariable=self._alert_count_var,
                 bg=BG, fg=RED,
                 font=("Courier New",10,"bold")).pack(side="left")
        tk.Button(bf, text=" Clear ", command=self._clear_alerts,
                  bg=BG2, fg=FG,
                  font=("Courier New",9), relief="flat").pack(side="right", padx=4)

        self._alert_tree = self._make_tree(
            frame,
            ["time","severity","type","src_ip","message"],
            ["Time","Severity","Type","Src IP","Message"]
        )
        self._alert_tree.column("message", width=480)
        for sev, col in [
            ("CRITICAL",RED),("HIGH",RED),("MEDIUM",YELLOW),
            ("LOW",ACCENT),("INFO",GREEN)
        ]:
            font = ("Courier New",9,"bold") if sev == "CRITICAL" else ("Courier New",9)
            self._alert_tree.tag_configure(sev, foreground=col, font=font)

    def _build_ai_tab(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=" 🤖 AI Results ")

        hf = tk.Frame(frame, bg=BG)
        hf.pack(fill="x", padx=8, pady=4)
        tk.Button(hf, text="← Home", command=lambda: self._nb.select(0),
                  bg=BG2, fg=ACCENT, font=("Courier New",9), relief="flat",
                  cursor="hand2").pack(side="left", padx=2)
        tk.Label(hf, text="AI Detection Log",
                 bg=BG, fg=ACCENT,
                 font=("Courier New",12,"bold")).pack(side="left")
        tk.Button(hf, text="  Train Models (Synthetic)  ",
                  command=self._train_models,
                  bg=BG2, fg=GREEN,
                  font=("Courier New",10),
                  relief="flat", cursor="hand2").pack(side="right", padx=4)

        self._ai_log = scrolledtext.ScrolledText(
            frame, bg=BG2, fg=FG,
            font=("Courier New",10),
            insertbackground=FG, relief="flat",
            state="disabled"
        )
        self._ai_log.pack(fill="both", expand=True, padx=8, pady=4)
        self._ai_log.tag_config("anomaly",   foreground=YELLOW)
        self._ai_log.tag_config("attack",    foreground=RED)
        self._ai_log.tag_config("normal",    foreground=GREEN)
        self._ai_log.tag_config("timestamp", foreground="#484f58")

    def _build_pcap_tab(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=" 📂 PCAP ")
        bf = tk.Frame(frame, bg=BG)
        bf.pack(fill="x", padx=8, pady=8)
        tk.Button(bf, text="← Home", command=lambda: self._nb.select(0),
                  bg=BG2, fg=ACCENT, font=("Courier New",9), relief="flat",
                  cursor="hand2").pack(side="left", padx=2)
        tk.Button(bf, text="  Import PCAP  ", command=self._import_pcap,
                  bg=BG2, fg=ACCENT,
                  font=("Courier New",10),
                  relief="flat", cursor="hand2").pack(side="left", padx=4)
        tk.Button(bf, text="  Export PCAP  ", command=self._export_pcap,
                  bg=BG2, fg=GREEN,
                  font=("Courier New",10),
                  relief="flat", cursor="hand2").pack(side="left", padx=4)
        self._pcap_text = scrolledtext.ScrolledText(
            frame, bg=BG2, fg=FG,
            font=("Courier New",10),
            relief="flat", state="disabled"
        )
        self._pcap_text.pack(fill="both", expand=True, padx=8, pady=4)

    # ── Wire & Start ──────────────────────────────────────────────────────────

    def _wire_and_start(self):
        """Connect all backend engines to the UI queues."""

        def on_packet(record):
            """Called by PacketSniffer for every captured packet."""
            self._pkt_count += 1
            # Always put in queue — no condition gate here
            try:
                self._pkt_queue.put_nowait(record)
            except queue.Full:
                # Drop oldest item, add new one
                try:
                    self._pkt_queue.get_nowait()
                    self._pkt_queue.put_nowait(record)
                except Exception:
                    pass

            # Detection on every packet
            self.arp_det.check(record)
            self.port_det.check(record)
            self.traffic_mon.update(record)
            self.topology.record_traffic(record.src_ip, record.dst_ip)

            # DB save every 10th
            if self._pkt_count % 10 == 0:
                try:
                    save_packet(record)
                except Exception:
                    pass

            # AI every 20th
            if self._pkt_count % 20 == 0:
                is_anom = False
                label   = "NORMAL"
                try:
                    is_anom = self.anomaly.predict(record)
                    label   = self.clf.classify(record)
                except Exception:
                    pass
                if is_anom or label not in ("NORMAL", "UNKNOWN"):
                    try:
                        self._ai_queue.put_nowait((record, is_anom, label))
                    except queue.Full:
                        pass

        def on_alert(alert):
            """Called by alert_manager for every new alert."""
            try:
                save_alert(alert)
            except Exception:
                pass
            try:
                self._alert_queue.put_nowait(alert)
            except queue.Full:
                pass

        def on_new_device(dev):
            """Called by NetworkScanner when a new device is found."""
            self.topology.add_device(dev)
            try:
                save_device(dev)
            except Exception:
                pass
            # Refresh device tab
            self.root.after(0, self._refresh_devices)

        # Register callbacks
        self.sniffer.add_callback(on_packet)
        subscribe(on_alert)
        self.scanner.on_new_device(on_new_device)

        # Start all engines
        self.traffic_mon.start()
        self.scanner.start()
        self.sniffer.start()
        self._running = True

        # Update UI state
        self._status_var.set("● LIVE")
        self._stop_btn.config(state="normal")
        log.info("GUI engines started on %s (subnet: %s)", self.interface, config.SUBNET)

    # ── Refresh Loop (every 300ms, main thread) ───────────────────────────────

    def _schedule_refresh(self):
        try:
            if self._running:
                self._flush_packets()
                self._flush_alerts()
                self._flush_ai()
            # Always refresh devices and stats (even after stop)
            self._refresh_devices()
            self._update_stats()
        except Exception:
            pass
        self.root.after(400, self._schedule_refresh)

    def _flush_packets(self):
        """Pull packets from queue and insert into treeview."""
        count = 0
        while not self._pkt_queue.empty() and count < 40:
            try:
                rec = self._pkt_queue.get_nowait()
            except queue.Empty:
                break
            ts  = time.strftime("%H:%M:%S", time.localtime(rec.timestamp))
            tag = rec.protocol if rec.protocol in ("TCP","UDP","DNS","ARP","ICMP") else "OTHER"
            try:
                self._pkt_tree.insert("", 0,
                    values=(
                        ts,
                        rec.src_ip or "N/A",
                        rec.dst_ip or "N/A",
                        rec.protocol or "?",
                        rec.app_protocol or "",
                        rec.packet_size,
                        (rec.info or "")[:80]
                    ),
                    tags=(tag,)
                )
            except tk.TclError:
                pass
            count += 1

        # Trim to 500 rows
        children = self._pkt_tree.get_children()
        if len(children) > 500:
            for item in children[500:]:
                self._pkt_tree.delete(item)

        # Update label
        self._pkt_label_var.set(f"{self._pkt_count:,} packets captured")

    def _flush_alerts(self):
        total = 0
        while not self._alert_queue.empty():
            try:
                a = self._alert_queue.get_nowait()
            except queue.Empty:
                break
            ts  = time.strftime("%H:%M:%S", time.localtime(a.get("timestamp", 0)))
            sev = a.get("severity","INFO")
            try:
                self._alert_tree.insert("", 0,
                    values=(
                        ts, sev,
                        a.get("type",""),
                        a.get("src_ip",""),
                        a.get("message","")[:100]
                    ),
                    tags=(sev,)
                )
            except tk.TclError:
                pass
            total += 1
        if total > 0:
            all_alerts = get_alerts(limit=500)
            self._alert_count_var.set(f"{len(all_alerts)} alerts total")

    def _flush_ai(self):
        while not self._ai_queue.empty():
            try:
                rec, is_anom, label = self._ai_queue.get_nowait()
            except queue.Empty:
                break
            self._ai_log.config(state="normal")
            ts = time.strftime("%H:%M:%S")
            if is_anom:
                self._ai_log.insert("end", f"[{ts}] ", "timestamp")
                self._ai_log.insert("end",
                    f"ANOMALY from {rec.src_ip} ({rec.protocol})\n",
                    "anomaly")
            if label not in ("NORMAL","UNKNOWN"):
                self._ai_log.insert("end", f"[{ts}] ", "timestamp")
                self._ai_log.insert("end",
                    f"ATTACK: {label} — {rec.src_ip} → {rec.dst_ip}:{rec.dst_port}\n",
                    "attack")
            self._ai_log.see("end")
            self._ai_log.config(state="disabled")

    def _update_stats(self):
        s = self.sniffer.get_stats()
        devs = self.scanner.get_devices()
        self._stats_var.set(
            f"Pkts: {s['total_captured']:,}  |  "
            f"{s['pps']} pps  |  "
            f"Devs: {len(devs)}  |  "
            f"Uptime: {s['elapsed_seconds']:.0f}s"
        )
        # Update window title with live stats
        alerts = get_alerts(limit=500)
        crit   = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        self.root.title(
            f"NetWatch SOC — {s['interface']} | "
            f"{s['total_captured']:,} pkts | "
            f"{len(alerts)} alerts"
            + (f" | ⚠ {crit} CRITICAL" if crit else "")
        )

    def _refresh_devices(self):
        """Refresh device treeview from scanner memory (thread-safe)."""
        try:
            devices = self.scanner.get_devices()
            # Cache so _update_stats can read without extra lock call
            self._cached_devices = devices
            if not devices:
                return
            # Only redraw if count changed (avoid flicker)
            current_count = len(self._dev_tree.get_children())
            if current_count == len(devices):
                return
            for item in self._dev_tree.get_children():
                self._dev_tree.delete(item)
            for d in devices:
                ts = time.strftime("%H:%M:%S", time.localtime(d.last_seen))
                self._dev_tree.insert("", "end",
                    values=(d.ip, d.mac, d.hostname or "N/A",
                            d.vendor or "Unknown", ts))
            self._dev_count_var.set(f"{len(devices)} devices found")
        except Exception:
            pass

    # ── Buttons ───────────────────────────────────────────────────────────────

    def _stop_all(self):
        """Stop all scanning engines."""
        if not self._running:
            return
        self._running = False
        self.sniffer.stop()
        self.traffic_mon.stop()
        self.scanner.stop()
        self._status_var.set("⏹ STOPPED")
        self._stop_btn.config(state="disabled", bg="#444")
        log.info("All engines stopped by user.")

    def _do_scan(self):
        """Manual ARP scan button."""
        def scan():
            devs = self.scanner.scan_now()
            self.root.after(0, self._refresh_devices)
        threading.Thread(target=scan, daemon=True).start()

    def _clear_alerts(self):
        for item in self._alert_tree.get_children():
            self._alert_tree.delete(item)
        self._alert_count_var.set("0 alerts")

    def _train_models(self):
        if not messagebox.askyesno(
            "Train AI",
            "Generate synthetic data and train AI models?\n"
            "This takes ~30 seconds."
        ):
            return

        def do_train():
            try:
                from ai_engine.model_trainer import generate_synthetic, train_all
                generate_synthetic()
                train_all()
                self.anomaly._load()
                self.clf._load()
                self.root.after(0, lambda: messagebox.showinfo(
                    "Training Complete",
                    "✅ AI models trained successfully!\n"
                    "Anomaly detection and attack classification are now active."
                ))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Training Error", str(e)))

        threading.Thread(target=do_train, daemon=True).start()

    def _import_pcap(self):
        path = filedialog.askopenfilename(
            title="Open PCAP file",
            filetypes=[("PCAP files","*.pcap *.pcapng"),("All","*.*")]
        )
        if not path:
            return
        summary = self.pcap.analyze_pcap(path)
        self._pcap_text.config(state="normal")
        self._pcap_text.delete("1.0","end")
        self._pcap_text.insert("end", json.dumps(summary, indent=2))
        self._pcap_text.config(state="disabled")

    def _export_pcap(self):
        path = filedialog.asksaveasfilename(
            title="Save PCAP",
            defaultextension=".pcap",
            filetypes=[("PCAP","*.pcap")]
        )
        if path:
            ok = self.sniffer.export_pcap(path)
            if ok:
                messagebox.showinfo("Export", f"PCAP saved to:\n{path}")
            else:
                messagebox.showerror("Export", "Export failed. Check logs.")

    def _on_close(self):
        self._stop_all()
        self.root.destroy()


def run_gui(interface: str = config.INTERFACE) -> None:
    root = tk.Tk()
    NetWatchGUI(root, interface=interface)
    root.mainloop()