"""
interface/web_dashboard.py — Flask + SocketIO SIEM Backend
FINAL FIX: All engines created INSIDE run_web() after interface is known.
           No module-level engine creation that uses wrong default interface.
"""
import os, time, threading

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

import config
from utils.alert_manager import get_alerts, subscribe
from core.network_intelligence import NetworkIntelligence
from utils.logger import get_logger

log = get_logger(__name__)

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
    static_folder  =os.path.join(os.path.dirname(__file__), "..", "static"),
)
app.config["SECRET_KEY"] = config.SECRET_KEY

socketio = SocketIO(
    app,
    cors_allowed_origins  = "*",
    async_mode            = "threading",
    logger                = False,
    engineio_logger       = False,
)

# ── Engine references — set by run_web() ──────────────────────────────────────
# These are None until run_web() is called with the correct interface.
_sniffer     = None
_scanner     = None
_arp_det     = None
_port_det    = None
_traffic_mon = None
_anomaly     = None
_classifier  = None
_topology    = None
_nmap        = None
_pcap        = None

_pkt_counter = 0
_intel: NetworkIntelligence = None
_initialized = False


def _get_engines():
    """Return engine tuple — safe to call from route handlers."""
    return (_sniffer, _scanner, _arp_det, _port_det,
            _traffic_mon, _anomaly, _classifier, _topology, _nmap, _pcap)


# ══════════════════════════════════════════════════════════════════════════════
# CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════

def _on_packet(record):
    global _pkt_counter
    _pkt_counter += 1

    if _arp_det:   _arp_det.check(record)
    if _port_det:  _port_det.check(record)
    if _traffic_mon: _traffic_mon.update(record)
    if _topology:  _topology.record_traffic(record.src_ip, record.dst_ip)
    if _intel and record.dns_query:
        _intel.update_app_from_dns(record.src_ip, record.dns_query)

    if _pkt_counter % 10 == 0:
        try:
            from database.storage import save_packet
            save_packet(record)
        except Exception:
            pass

    # AI label: empty string means AI did not run this packet
    # Frontend only updates classifier bars when ai_label is non-empty
    ai_label = ""
    if _pkt_counter % 20 == 0:
        try:
            if _anomaly:    _anomaly.predict(record)
            if _classifier: ai_label = _classifier.classify(record)
        except Exception:
            pass

    try:
        socketio.emit("new_packet", {**record.to_dict(), "ai_label": ai_label})
    except Exception:
        pass


def _on_alert(alert):
    try:
        from database.storage import save_alert
        save_alert(alert)
    except Exception:
        pass
    try:
        socketio.emit("new_alert", alert)
    except Exception:
        pass


def _on_new_device(device):
    if _topology: _topology.add_device(device)
    try:
        from database.storage import save_device
        save_device(device)
    except Exception:
        pass
    try:
        devs = _scanner.get_devices() if _scanner else []
        socketio.emit("devices_updated", [d.to_dict() for d in devs])
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    from database.storage import get_packet_count
    s = _sniffer.get_stats() if _sniffer else {"total_captured":0,"elapsed_seconds":0,"pps":0,"interface":"N/A","running":False}
    s.update({
        "alert_count":  len(get_alerts()),
        "device_count": len(_scanner.get_devices()) if _scanner else 0,
        "db_pkt_count": get_packet_count(),
    })
    return jsonify(s)


@app.route("/api/devices")
def api_devices():
    from database.storage import get_all_devices
    live = [d.to_dict() for d in (_scanner.get_devices() if _scanner else [])]
    return jsonify(live if live else get_all_devices())


@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(get_alerts(limit=limit))


@app.route("/api/topology")
def api_topology():
    data = _topology.to_d3_json() if _topology else {"nodes":[],"links":[]}
    return jsonify(data)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    def do():
        if not _scanner: return
        devices = _scanner.scan_now()
        if _topology:
            for d in devices: _topology.add_device(d)
        socketio.emit("devices_updated", [d.to_dict() for d in devices])
        socketio.emit("scan_complete", {"count": len(devices)})
    threading.Thread(target=do, daemon=True).start()
    return jsonify({"status": "scan_started"})


@app.route("/api/nmap", methods=["POST"])
def api_nmap():
    data   = request.get_json() or {}
    target = data.get("target", config.GATEWAY)
    ports  = data.get("ports", "1-1024")
    args   = data.get("args", "-sV -T4")

    def do():
        if not _nmap:
            socketio.emit("nmap_results", {"target": target, "results": [{"error": "Nmap not initialized"}]})
            return
        results = _nmap.scan_host(target, ports=ports, args=args)
        socketio.emit("nmap_results", {"target": target, "results": results})
    threading.Thread(target=do, daemon=True).start()
    return jsonify({"status": "nmap_started", "target": target})


@app.route("/api/pcap/analyze", methods=["POST"])
def api_pcap_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f    = request.files["file"]
    path = f"/tmp/nw_{int(time.time())}.pcap"
    f.save(path)
    result = _pcap.analyze_pcap(path) if _pcap else {"error": "not initialized"}
    try: os.remove(path)
    except Exception: pass
    return jsonify(result)


@app.route("/api/pcap/export", methods=["POST"])
def api_pcap_export():
    if not _sniffer:
        return jsonify({"error": "sniffer not running"})
    fname = f"export_{int(time.time())}.pcap"
    path  = os.path.join(config.PCAP_EXPORT_DIR, fname)
    ok    = _sniffer.export_pcap(path)
    return jsonify({"status": "ok" if ok else "error", "file": path})


@app.route("/api/train", methods=["POST"])
def api_train():
    data      = request.get_json() or {}
    synthetic = data.get("synthetic", False)

    def do():
        try:
            from ai_engine.model_trainer import train_all, generate_synthetic
            if synthetic:
                generate_synthetic()
            train_all()
            if _anomaly:    _anomaly._load()
            if _classifier: _classifier._load()
            socketio.emit("training_complete", {"status": "done"})
        except Exception as e:
            socketio.emit("training_complete", {"status": "error", "message": str(e)})
    threading.Thread(target=do, daemon=True).start()
    return jsonify({"status": "training_started"})


@app.route("/api/arp_table")
def api_arp_table():
    return jsonify(_arp_det.get_table() if _arp_det else {})


# ══════════════════════════════════════════════════════════════════════════════
# SOCKETIO EVENTS
# ══════════════════════════════════════════════════════════════════════════════


@app.route("/devices-intel")
def devices_intel():
    return render_template("devices.html")


@app.route("/api/intel/info")
def api_intel_info():
    """Return local network info + all discovered devices."""
    net_info = _intel.detect_local_network().to_dict() if _intel else {}
    devices  = [d.to_dict() for d in (_intel.get_devices() if _intel else [])]
    return jsonify({"net_info": net_info, "devices": devices})


@app.route("/api/intel/scan", methods=["POST"])
def api_intel_scan():
    """Start a background network intelligence scan."""
    data = request.get_json() or {}
    deep = data.get("deep", False)

    def do_scan():
        if not _intel:
            return
        def progress_cb(done, total, ip):
            socketio.emit("scan_progress", {"done": done, "total": total, "current_ip": ip})
        def device_cb(dev):
            socketio.emit("device_update", dev.to_dict())
        _intel.on_device_update(device_cb)
        devices = _intel.scan_all_devices(deep_scan=deep, progress_cb=progress_cb)
        socketio.emit("scan_complete", {"count": len(devices)})

    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"status": "started", "deep": deep})

@socketio.on("connect")
def handle_connect():
    log.info("Client connected: %s", request.sid)
    from database.storage import get_all_devices
    devs = [d.to_dict() for d in (_scanner.get_devices() if _scanner else [])]
    if not devs:
        devs = get_all_devices()
    stats = _sniffer.get_stats() if _sniffer else {}
    emit("init_data", {
        "stats":    stats,
        "alerts":   get_alerts(limit=20),
        "devices":  devs,
        "topology": _topology.to_d3_json() if _topology else {"nodes":[],"links":[]},
    })


@socketio.on("disconnect")
def handle_disconnect():
    log.info("Client disconnected: %s", request.sid)


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP — engines created HERE with correct interface
# ══════════════════════════════════════════════════════════════════════════════

def run_web(interface: str = config.INTERFACE,
            host: str      = config.WEB_HOST,
            port: int      = config.WEB_PORT) -> None:
    """
    Create ALL engines with the correct interface, then start Flask.
    Engines are NOT created at module level to avoid wrong-interface problem.
    """
    global _sniffer, _scanner, _arp_det, _port_det, _traffic_mon
    global _anomaly, _classifier, _topology, _nmap, _pcap
    global _initialized

    if _initialized:
        log.warning("run_web called twice — ignoring")
        return

    # Ensure config is set
    config.INTERFACE = interface

    log.info("Creating engines with interface=%s subnet=%s", interface, config.SUBNET)

    # ── Create engines NOW (interface is known) ───────────────────────────────
    from core.packet_sniffer    import PacketSniffer
    from core.network_scanner   import NetworkScanner
    from detection.arp_spoof_detector import ARPSpoofDetector
    from detection.port_scan_detector import PortScanDetector
    from detection.traffic_monitor    import TrafficMonitor
    from ai_engine.anomaly_detector   import AnomalyDetector
    from ai_engine.attack_classifier  import AttackClassifier
    from visualization.topology_mapper import TopologyMapper
    from integrations.nmap_scanner    import NmapScanner
    from integrations.pcap_handler    import PCAPHandler
    from database.storage             import get_all_devices

    global _intel
    _intel = NetworkIntelligence()
    _intel.detect_local_network()
    # Wire DNS app tracking from sniffer

    _sniffer     = PacketSniffer(interface=interface)
    _scanner     = NetworkScanner(subnet=config.SUBNET, interface=interface)
    _arp_det     = ARPSpoofDetector()
    # Thresholds tuned for real networks:
    # - DDoS: 1500 pps per source IP (eliminates false positives from DNS/browsing)
    # - Port scan: 20 unique ports in 5s (catches nmap, skips normal traffic)
    _port_det    = PortScanDetector(threshold=20, window=5)
    _traffic_mon = TrafficMonitor(threshold=1500)
    _anomaly     = AnomalyDetector()
    _classifier  = AttackClassifier()
    _topology    = TopologyMapper(gateway=config.GATEWAY)
    _nmap        = NmapScanner()
    _pcap        = PCAPHandler()

    # ── Wire callbacks ────────────────────────────────────────────────────────
    _sniffer.add_callback(_on_packet)
    subscribe(_on_alert)
    _scanner.on_new_device(_on_new_device)

    # ── Pre-populate topology from DB ─────────────────────────────────────────
    for dev in get_all_devices():
        class _D: pass
        d = _D()
        d.ip = dev.get("ip",""); d.hostname = dev.get("hostname","")
        d.mac = dev.get("mac","N/A"); d.vendor = dev.get("vendor","Unknown")
        _topology.add_device(d)

    # ── Start engines ─────────────────────────────────────────────────────────
    _traffic_mon.start()
    _scanner.start()
    _sniffer.start()
    _initialized = True

    log.info("="*60)
    log.info("NetWatch SOC | Interface: %s | Subnet: %s", interface, config.SUBNET)
    log.info("URL: http://127.0.0.1:%d", port)
    log.info("="*60)

    # ── Find free port ────────────────────────────────────────────────────────
    import socket as _sock
    actual_port = port
    for try_port in [port, 5001, 5002, 5003, 8080, 8888]:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", try_port))
            s.close()
            actual_port = try_port
            break
        except OSError:
            log.warning("Port %d busy, trying %d ...", try_port, try_port+1)

    if actual_port != port:
        print(f"\n  ⚠ Port {port} busy — using port {actual_port}")
    print(f"  Open browser → http://127.0.0.1:{actual_port}\n")

    socketio.run(
        app,
        host                  = host,
        port                  = actual_port,
        debug                 = False,
        use_reloader          = False,
        allow_unsafe_werkzeug = True,
    )