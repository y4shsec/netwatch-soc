"""
config.py — Global Configuration
Edit INTERFACE and SUBNET to match your network before running.
"""
import os

# dotenv is optional — if not installed, values are read from environment
# or fall back to the defaults below. Edit defaults directly if needed.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

INTERFACE        = os.getenv("INTERFACE", "eth0")
SUBNET           = os.getenv("SUBNET", "192.168.1.0/24")
GATEWAY          = os.getenv("GATEWAY", "192.168.1.1")
PACKET_STORE_MAX = 10_000

WEB_HOST         = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT         = int(os.getenv("WEB_PORT", 5000))
SECRET_KEY       = os.getenv("SECRET_KEY", "netwatch-soc-secret")

DB_PATH          = "database/logs.db"
DB_URL           = f"sqlite:///{DB_PATH}"

MODEL_DIR        = "models/"
ANOMALY_MODEL    = "models/anomaly_model.pkl"
CLASSIFIER_MODEL = "models/attack_classifier.pkl"
SCALER_MODEL     = "models/scaler.pkl"
LABEL_ENCODER    = "models/label_encoder.pkl"

DATASET_DIR      = "data/cicids2017/"

ALERT_PPS_THRESHOLD  = 1500  # pps per source IP → DDoS alert. Set higher for busy networks.
PORT_SCAN_THRESHOLD  = 20    # unique ports in window → port scan alert
PORT_SCAN_WINDOW_SEC = 5     # seconds for port scan detection window

PROTOCOL_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

LOG_LEVEL     = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE      = "logs/netwatch.log"
PCAP_EXPORT_DIR = "captures/"