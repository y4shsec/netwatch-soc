"""
main.py — NetWatch SOC Entry Point

Run: sudo -E env PATH=$PATH python3 main.py
"""
import os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── Dependency check ──────────────────────────────────────────────────────────
REQUIRED = [
    ("scapy","scapy"),("flask","flask"),("flask_socketio","flask-socketio"),
    ("sklearn","scikit-learn"),("rich","rich"),("sqlalchemy","sqlalchemy"),
    ("nmap","python-nmap"),("pandas","pandas"),("numpy","numpy"),
    ("joblib","joblib"),("networkx","networkx"),("psutil","psutil"),
]
missing = []
for mod, pkg in REQUIRED:
    try: __import__(mod)
    except ImportError: missing.append(pkg)
if missing:
    print(f"\n❌ Missing packages:\n   pip3 install {' '.join(missing)}\n")
    print("With sudo+venv:  sudo -E env PATH=$PATH python3 main.py\n")
    sys.exit(1)

# Suppress pandas PyArrow deprecation warning (harmless, just noisy)
import warnings
warnings.filterwarnings("ignore", message=".*pyarrow.*", category=DeprecationWarning)

import config
from utils.logger import get_logger
log = get_logger(__name__)

BANNER = """
  _   _      _  __        __    _       _      ____   ___   ____
 | \\ | | ___| |_\\ \\      / /_ _| |_ ___| |__  / ___| / _ \\ / ___|
 |  \\| |/ _ \\ __|\\ \\ /\\ / / _` | __/ __| '_ \\ \\___ \\| | | | |
 | |\\  |  __/ |_  \\ V  V / (_| | || (__| | | | ___) | |_| | |___
 |_| \\_|\\___|\\__|  \\_/\\_/ \\__,_|\\__\\___|_| |_||____/ \\___/ \\____|
         Professional Network Security Monitoring Platform
"""


def print_banner():
    try:
        from rich.console import Console
        from rich.panel import Panel
        Console().print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    except ImportError:
        print(BANNER)


def _get_interfaces_with_ip() -> dict:
    """Return dict of {interface_name: ip_address} using psutil."""
    import psutil
    SKIP = ("lo","docker","virbr","veth","br-","tailscale","tun","tap","vmnet","dummy","bond")
    result = {}
    for name, addrs in psutil.net_if_addrs().items():
        if any(name.startswith(s) for s in SKIP):
            continue
        for addr in addrs:
            if addr.family == 2:   # AF_INET = IPv4
                if not addr.address.startswith(("127.","169.254.","0.")):
                    result[name] = addr.address
                    break
    return result


def _detect_subnet(iface: str) -> str:
    """Detect /CIDR subnet for interface using psutil."""
    import psutil, ipaddress
    try:
        for addr in psutil.net_if_addrs().get(iface, []):
            if addr.family == 2 and addr.address and addr.netmask:
                if addr.address.startswith(("127.","0.")): continue
                net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                print(f"  ✓ {iface} → {addr.address}  subnet: {net}")
                return str(net)
    except Exception as e:
        log.debug("subnet detect error: %s", e)
    print(f"  ⚠ Could not detect subnet for '{iface}' — using: {config.SUBNET}")
    return config.SUBNET


def pick_interface() -> tuple:
    """Show available interfaces with IPs. Returns (iface_name, subnet)."""
    iface_map = _get_interfaces_with_ip()   # {name: ip}

    if not iface_map:
        print("  ⚠ No interfaces with IP found — using config defaults")
        return config.INTERFACE, config.SUBNET

    # Sort: wlan/wifi first, then eth/enp, then rest
    def priority(n):
        if n.startswith(("wlan","wifi","wlp")): return 0
        if n.startswith(("eth","enp","ens","eno")): return 1
        return 2

    names = sorted(iface_map.keys(), key=priority)

    print("\n  Available network interfaces:")
    print(f"  {'':2} {'#':<4} {'Interface':<16} {'IP Address'}")
    print("  " + "─"*42)
    for i, name in enumerate(names, 1):
        arrow = "→" if i == 1 else " "
        print(f"  {arrow} [{i}]  {name:<16} {iface_map[name]}")

    default = names[0]
    print(f"\n  Default: [{1}] {default}")
    choice = input("\n  Enter number or name [Enter = default]: ").strip()

    if not choice:
        selected = default
    elif choice.isdigit():
        idx = int(choice) - 1
        selected = names[idx] if 0 <= idx < len(names) else default
    elif choice in names:
        selected = choice
    else:
        print(f"  ⚠ '{choice}' not found — using: {default}")
        selected = default

    print(f"\n  Selected: {selected}  ({iface_map.get(selected,'?')})")
    subnet = _detect_subnet(selected)
    return selected, subnet


def startup_menu() -> tuple:
    """Show mode menu. Returns (mode, iface, subnet)."""
    print("\n" + "="*50)
    print("  NetWatch SOC — Network Security Monitor")
    print("="*50 + "\n")
    print("  Select Mode:\n")
    print("    1.  CLI Mode          (terminal dashboard)")
    print("    2.  GUI Mode          (desktop window)")
    print("    3.  Web Dashboard     (browser SIEM)")
    print("    4.  Train AI Models")
    print("    5.  Exit\n")
    while True:
        c = input("  Enter choice [1-5]: ").strip()
        if c in ("1","2","3","4","5"): break
        print("  Please enter 1–5.")
    if c == "5":
        print("\n  Goodbye.\n"); sys.exit(0)
    if c in ("1","2","3"):
        iface, subnet = pick_interface()
    else:
        iface, subnet = config.INTERFACE, config.SUBNET
    return {"1":"cli","2":"gui","3":"web","4":"train"}[c], iface, subnet


def main():
    import argparse
    p = argparse.ArgumentParser(description="NetWatch SOC")
    p.add_argument("--mode",      choices=["cli","gui","web"])
    p.add_argument("--interface", default=None)
    p.add_argument("--subnet",    default=None)
    p.add_argument("--train",     action="store_true")
    p.add_argument("--synthetic", action="store_true")
    args = p.parse_args()

    print_banner()

    if args.train:
        _do_train(args.synthetic); return

    if args.mode:
        iface  = args.interface or config.INTERFACE
        subnet = args.subnet or _detect_subnet(iface)
        _launch(args.mode, iface, subnet); return

    mode, iface, subnet = startup_menu()
    print(f"\n  ✓ Mode: {mode.upper()}  |  Interface: {iface}  |  Subnet: {subnet}\n")

    try:
        if mode == "train": _do_train(False)
        else: _launch(mode, iface, subnet)
    except KeyboardInterrupt:
        print("\n\n  Stopped. Goodbye.\n")
    except PermissionError:
        print("\n  ❌ Permission denied.\n  Run: sudo -E env PATH=$PATH python3 main.py\n")
        sys.exit(1)
    except Exception as e:
        log.exception("Fatal: %s", e); sys.exit(1)


def _launch(mode: str, iface: str, subnet: str):
    # Validate interface
    if not iface or len(iface) < 2 or iface.startswith("~"):
        iface_map = _get_interfaces_with_ip()
        if iface_map:
            iface  = list(iface_map.keys())[0]
            subnet = _detect_subnet(iface)
            print(f"  ⚠ Auto-corrected interface to: {iface}")
        else:
            print("  ❌ No valid interface found. Check your network."); sys.exit(1)

    config.INTERFACE = iface
    config.SUBNET    = subnet
    print(f"  Running on: {iface}  |  Subnet: {subnet}")

    if mode == "cli":
        from interface.cli import run_cli
        run_cli(interface=iface)
    elif mode == "gui":
        try: import tkinter
        except ImportError:
            print("❌ Tkinter: sudo apt install python3-tk"); sys.exit(1)
        from interface.gui import run_gui
        run_gui(interface=iface)
    elif mode == "web":
        from interface.web_dashboard import run_web
        print(f"  Open browser → http://127.0.0.1:{config.WEB_PORT}\n")
        run_web(interface=iface)


def _do_train(synthetic: bool):
    import glob
    from ai_engine.model_trainer import train_all, generate_synthetic
    has = bool(glob.glob(os.path.join(config.DATASET_DIR, "*.csv")))
    if synthetic or not has:
        if not has and not synthetic:
            print(f"\n  No CSV in {config.DATASET_DIR}")
            print("  Download: https://www.kaggle.com/datasets/cicdataset/cicids2017")
            if input("\n  Use synthetic demo data? [y/N]: ").strip().lower() != "y":
                print("  Aborted."); return
        generate_synthetic()
    print("\n  🤖 Training …\n")
    train_all()
    print(f"\n  ✅ Models saved to {config.MODEL_DIR}\n")


if __name__ == "__main__":
    main()