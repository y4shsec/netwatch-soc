import re, socket, struct, requests
from functools import lru_cache
from utils.logger import get_logger
log = get_logger(__name__)

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

@lru_cache(maxsize=512)
def get_mac_vendor(mac: str) -> str:
    try:
        oui = mac.upper().replace(":", "").replace("-", "")[:6]
        r = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return "Unknown Vendor"

def mac_normalise(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    return ":".join(clean[i:i+2] for i in range(0, 12, 2)).upper()
