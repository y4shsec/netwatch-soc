"""
ai_engine/anomaly_detector.py
Isolation Forest inference — flags unusual packets as anomalies.
"""
import numpy as np, joblib
import config
from ai_engine.feature_extractor import extract_features
from utils.alert_manager import push_alert
from utils.logger import get_logger
log = get_logger(__name__)


class AnomalyDetector:
    def __init__(self):
        self.model = self.scaler = None
        self.ready = False
        self._load()

    def _load(self):
        try:
            self.model  = joblib.load(config.ANOMALY_MODEL)
            self.scaler = joblib.load(config.SCALER_MODEL)
            self.ready  = True
            log.info("Anomaly model loaded.")
        except FileNotFoundError:
            log.warning("Anomaly model not found — run: python main.py --train")

    def predict(self, record, flow_stats=None) -> bool:
        if not self.ready:
            return False
        try:
            X  = np.array([extract_features(record, flow_stats)])
            Xs = self.scaler.transform(X)
            if self.model.predict(Xs)[0] == -1:
                push_alert(
                    severity="MEDIUM", alert_type="AI_ANOMALY", src_ip=record.src_ip,
                    message=f"AI Anomaly: unusual traffic from {record.src_ip} "
                            f"({record.protocol} → {record.dst_ip}:{record.dst_port})",
                )
                return True
        except Exception as e:
            log.debug("Anomaly detect error: %s", e)
        return False
