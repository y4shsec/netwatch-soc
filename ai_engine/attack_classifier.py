"""
ai_engine/attack_classifier.py
Random Forest inference — classifies traffic into attack categories.
"""
import numpy as np, joblib
import config
from ai_engine.feature_extractor import extract_features
from utils.alert_manager import push_alert
from utils.logger import get_logger
log = get_logger(__name__)

MESSAGES = {
    "DDOS":        "Possible DDoS attack from {ip}",
    "PORT_SCAN":   "Port scanning activity from {ip}",
    "BRUTE_FORCE": "Brute force attempt from {ip} → port {dport}",
    "MALWARE_C2":  "Possible malware C2 traffic from {ip} → {dst}",
    "OTHER":       "Suspicious traffic from {ip}",
}
SEVERITIES = {
    "DDOS":"HIGH","PORT_SCAN":"HIGH","BRUTE_FORCE":"HIGH",
    "MALWARE_C2":"CRITICAL","OTHER":"MEDIUM",
}


class AttackClassifier:
    def __init__(self):
        self.model = self.scaler = self.encoder = None
        self.ready = False
        self._load()

    def _load(self):
        try:
            self.model   = joblib.load(config.CLASSIFIER_MODEL)
            self.scaler  = joblib.load(config.SCALER_MODEL)
            self.encoder = joblib.load(config.LABEL_ENCODER)
            self.ready   = True
            log.info("Attack classifier loaded.")
        except FileNotFoundError:
            log.warning("Classifier not found — run: python main.py --train")

    def classify(self, record, flow_stats=None) -> str:
        if not self.ready:
            return "UNKNOWN"
        try:
            X     = np.array([extract_features(record, flow_stats)])
            Xs    = self.scaler.transform(X)
            label = self.encoder.inverse_transform(self.model.predict(Xs))[0]
            if label != "NORMAL":
                msg = MESSAGES.get(label, MESSAGES["OTHER"]).format(
                    ip=record.src_ip, dport=record.dst_port, dst=record.dst_ip
                )
                push_alert(
                    severity=SEVERITIES.get(label, "MEDIUM"),
                    alert_type=f"AI_{label}",
                    src_ip=record.src_ip,
                    message=msg,
                    details={"label": label, "dst": record.dst_ip, "port": record.dst_port},
                )
            return label
        except Exception as e:
            log.debug("Classify error: %s", e)
            return "UNKNOWN"

    def get_proba(self, record, flow_stats=None) -> dict:
        if not self.ready:
            return {}
        try:
            X     = np.array([extract_features(record, flow_stats)])
            Xs    = self.scaler.transform(X)
            probs = self.model.predict_proba(Xs)[0]
            classes = self.encoder.inverse_transform(range(len(probs)))
            return {c: round(float(p), 4) for c, p in zip(classes, probs)}
        except Exception:
            return {}
