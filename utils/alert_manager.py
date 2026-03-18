"""
utils/alert_manager.py
Central alert bus. Every detection module calls push_alert().
The web dashboard subscribes via subscribe() to get live pushes.
"""
import uuid, time
from collections import deque
from threading import Lock
from typing import Callable, List, Optional

from utils.logger import get_logger
log = get_logger(__name__)

_alerts: deque = deque(maxlen=500)
_lock = Lock()
_subscribers: List[Callable] = []

SEVERITY_COLOUR = {
    "CRITICAL": "bold red", "HIGH": "red",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green",
}

def push_alert(severity: str, alert_type: str, message: str,
               src_ip: str = "N/A", details: Optional[dict] = None) -> dict:
    alert = {
        "id":        str(uuid.uuid4()),
        "timestamp": time.time(),
        "severity":  severity.upper(),
        "type":      alert_type,
        "src_ip":    src_ip,
        "message":   message,
        "details":   details or {},
    }
    with _lock:
        _alerts.appendleft(alert)
    log.warning("[ALERT][%s] %s — %s", severity, alert_type, message)
    for cb in list(_subscribers):
        try:
            cb(alert)
        except Exception as e:
            log.error("Alert subscriber error: %s", e)
    return alert

def get_alerts(limit: int = 50) -> List[dict]:
    with _lock:
        return list(_alerts)[:limit]

def clear_alerts():
    with _lock:
        _alerts.clear()

def subscribe(callback: Callable):
    if callback not in _subscribers:
        _subscribers.append(callback)

def unsubscribe(callback: Callable):
    if callback in _subscribers:
        _subscribers.remove(callback)
