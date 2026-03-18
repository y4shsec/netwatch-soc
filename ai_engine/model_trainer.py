"""
ai_engine/model_trainer.py — Complete Training Pipeline
Supports both real CIC-IDS-2017 data and synthetic demo data.

RUN:
    python main.py --train              (real dataset in data/cicids2017/)
    python main.py --train --synthetic  (no dataset needed)
"""
import os, glob
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import config
from ai_engine.feature_extractor import CICIDS_COLS, CICIDS_LABEL, map_label
from utils.logger import get_logger

log = get_logger(__name__)
os.makedirs(config.MODEL_DIR, exist_ok=True)


# ── 1. Load Dataset ────────────────────────────────────────────────────────────

def load_dataset(dataset_dir: str = config.DATASET_DIR) -> pd.DataFrame:
    files = glob.glob(os.path.join(dataset_dir, "*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files in {dataset_dir}\n"
            "Download from https://www.kaggle.com/datasets/cicdataset/cicids2017\n"
            "OR run: python main.py --train --synthetic"
        )
    log.info("Loading %d CSV files …", len(files))
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)
        log.info("  Loaded %s (%d rows)", os.path.basename(f), len(df))
    combined = pd.concat(frames, ignore_index=True)
    log.info("Total rows: %d", len(combined))
    return combined


def preprocess(df: pd.DataFrame):
    df.columns = df.columns.str.strip()
    available  = [c for c in CICIDS_COLS if c in df.columns]
    label_col  = CICIDS_LABEL.strip()
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found.")
    df = df[available + [label_col]].copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    X  = df[available].values.astype(np.float32)
    y  = df[label_col].apply(map_label).values
    log.info("Feature shape: %s", X.shape)
    for cls in np.unique(y):
        log.info("  %-15s: %d", cls, (y == cls).sum())
    return X, y, available


# ── 2. Train Models ────────────────────────────────────────────────────────────

def train_anomaly(X_normal: np.ndarray) -> IsolationForest:
    log.info("Training Isolation Forest …")
    m = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    m.fit(X_normal)
    log.info("Anomaly detector trained.")
    return m


def train_classifier(X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
    log.info("Training Random Forest classifier …")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)
    log.info("Accuracy: %.2f%%", accuracy_score(y_te, y_pred) * 100)
    log.info("\n%s", classification_report(y_te, y_pred))
    return clf


# ── 3. Full Pipeline ───────────────────────────────────────────────────────────

def train_all(dataset_dir: str = config.DATASET_DIR) -> None:
    df       = load_dataset(dataset_dir)
    X, y, fc = preprocess(df)

    scaler   = StandardScaler()
    Xs       = scaler.fit_transform(X)
    le       = LabelEncoder()
    le.fit(y)

    # ── Anomaly Detector: train on NORMAL samples only ───────────────────────
    normal_mask  = (y == "NORMAL")
    normal_count = normal_mask.sum()
    log.info("NORMAL samples available for anomaly training: %d", normal_count)

    if normal_count == 0:
        # Fallback: if no NORMAL label, use the majority class
        unique, counts = np.unique(y, return_counts=True)
        majority_label = unique[np.argmax(counts)]
        log.warning(
            "No NORMAL samples found! Using majority class '%s' (%d samples) as baseline.",
            majority_label, counts.max()
        )
        normal_mask = (y == majority_label)

    X_normal      = Xs[normal_mask]
    anomaly_model = train_anomaly(X_normal)

    # ── Attack Classifier: train on all classes ───────────────────────────────
    classifier = train_classifier(Xs, y)

    # ── Save everything ───────────────────────────────────────────────────────
    joblib.dump(scaler,        config.SCALER_MODEL)
    joblib.dump(anomaly_model, config.ANOMALY_MODEL)
    joblib.dump(classifier,    config.CLASSIFIER_MODEL)
    joblib.dump(le,            config.LABEL_ENCODER)
    joblib.dump(fc,            os.path.join(config.MODEL_DIR, "feature_cols.pkl"))

    log.info("✅ All models saved to %s", config.MODEL_DIR)


# ── 4. Synthetic Dataset ───────────────────────────────────────────────────────

def generate_synthetic(n: int = 6000) -> None:
    log.warning("Generating SYNTHETIC dataset (demo only, not real traffic).")
    rng = np.random.default_rng(42)
    specs = {
        "NORMAL":      {"pkt": (40,800),  "port_dst": [80,443,53,22,25], "syn":False, "pps":(1,100)},
        "DDOS":        {"pkt": (40,100),  "port_dst": [80,443],          "syn":True,  "pps":(500,5000)},
        "PORT_SCAN":   {"pkt": (40,80),   "port_dst": None,              "syn":True,  "pps":(100,1000)},
        "BRUTE_FORCE": {"pkt": (100,300), "port_dst": [22,21,23,3389],   "syn":False, "pps":(10,200)},
        "MALWARE_C2":  {"pkt": (50,400),  "port_dst": [443,80,8080,6667],"syn":False, "pps":(1,30)},
    }
    counts = {"NORMAL":3000,"DDOS":700,"PORT_SCAN":600,"BRUTE_FORCE":400,"MALWARE_C2":300}
    rows = []
    for label, cnt in counts.items():
        sp = specs[label]
        for _ in range(cnt):
            pkt_size  = rng.integers(*sp["pkt"])
            dst_port  = int(rng.choice(sp["port_dst"])) if sp["port_dst"] else int(rng.integers(1,65535))
            syn_count = int(rng.integers(1,5)) if sp["syn"] else 0
            pps       = rng.uniform(*sp["pps"])
            rows.append({
                "Total Length of Fwd Packets": pkt_size,
                "Total Length of Bwd Packets": int(rng.integers(0, pkt_size)),
                "Source Port":                 int(rng.integers(1024, 65535)),
                "Destination Port":            dst_port,
                "Protocol":                    int(rng.choice([6, 17])),
                "SYN Flag Count":              syn_count,
                "ACK Flag Count":              int(rng.integers(0,5)),
                "FIN Flag Count":              int(rng.integers(0,2)),
                "RST Flag Count":              int(rng.integers(0,2)),
                "Flow Packets/s":              round(float(pps), 2),
                "Flow Bytes/s":                round(float(pps * pkt_size), 2),
                "Total Fwd Packets":           int(rng.integers(1, 100)),
                "Total Backward Packets":      int(rng.integers(0, 50)),
                "Label":                       label,
            })
    os.makedirs(config.DATASET_DIR, exist_ok=True)
    out = os.path.join(config.DATASET_DIR, "synthetic.csv")
    pd.DataFrame(rows).to_csv(out, index=False)
    log.info("Synthetic dataset saved: %s (%d rows)", out, len(rows))


if __name__ == "__main__":
    import sys
    if "--synthetic" in sys.argv or not glob.glob(os.path.join(config.DATASET_DIR, "*.csv")):
        generate_synthetic()
    train_all()