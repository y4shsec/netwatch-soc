"""
database/storage.py — SQLite Persistent Storage
All data is auto-saved here. Tables are created on first run.
"""
import os, time, json
from typing import List
from sqlalchemy import (
    create_engine, Column, Integer, Float, String, Text, Index
)
from sqlalchemy.orm import DeclarativeBase, Session
import config
from utils.logger import get_logger

log = get_logger(__name__)
os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
engine = create_engine(config.DB_URL, echo=False, connect_args={"check_same_thread": False})


class Base(DeclarativeBase):
    pass


class DeviceRecord(Base):
    __tablename__ = "devices"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    ip         = Column(String(45), unique=True, nullable=False, index=True)
    mac        = Column(String(17))
    hostname   = Column(String(255))
    vendor     = Column(String(255))
    os_guess   = Column(String(255))
    open_ports = Column(Text)
    first_seen = Column(Float)
    last_seen  = Column(Float)


class PacketLog(Base):
    __tablename__ = "packet_logs"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    timestamp      = Column(Float, nullable=False)
    src_ip         = Column(String(45))
    dst_ip         = Column(String(45))
    protocol       = Column(String(20))
    app_protocol   = Column(String(20))
    src_port       = Column(Integer)
    dst_port       = Column(Integer)
    packet_size    = Column(Integer)
    payload_length = Column(Integer)
    info           = Column(Text)
    __table_args__ = (
        Index("ix_plog_ts",  "timestamp"),
        Index("ix_plog_src", "src_ip"),
    )


class AlertRecord(Base):
    __tablename__ = "alerts"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    alert_uuid = Column(String(36), unique=True)
    timestamp  = Column(Float)
    severity   = Column(String(20))
    alert_type = Column(String(50))
    src_ip     = Column(String(45))
    message    = Column(Text)
    details    = Column(Text)
    __table_args__ = (
        Index("ix_alert_sev", "severity"),
        Index("ix_alert_ts",  "timestamp"),
    )


Base.metadata.create_all(engine)
log.info("Database ready at %s", config.DB_PATH)


# ── Write helpers ──────────────────────────────────────────────────────────────

def save_device(dev) -> None:
    """Upsert a DeviceInfo into the devices table."""
    with Session(engine) as s:
        existing = s.query(DeviceRecord).filter_by(ip=dev.ip).first()
        if existing:
            existing.mac       = dev.mac
            existing.hostname  = dev.hostname
            existing.vendor    = dev.vendor
            existing.last_seen = time.time()
        else:
            s.add(DeviceRecord(
                ip=dev.ip, mac=dev.mac, hostname=dev.hostname,
                vendor=dev.vendor, open_ports=json.dumps(dev.ports or []),
                first_seen=dev.first_seen or time.time(), last_seen=time.time(),
            ))
        s.commit()


def save_packet(record) -> None:
    """Persist a PacketRecord summary to the DB (not raw bytes)."""
    with Session(engine) as s:
        s.add(PacketLog(
            timestamp=record.timestamp, src_ip=record.src_ip, dst_ip=record.dst_ip,
            protocol=record.protocol, app_protocol=record.app_protocol,
            src_port=record.src_port, dst_port=record.dst_port,
            packet_size=record.packet_size, payload_length=record.payload_length,
            info=record.info,
        ))
        s.commit()


def save_alert(alert: dict) -> None:
    """Persist an alert dict."""
    with Session(engine) as s:
        if not s.query(AlertRecord).filter_by(alert_uuid=alert.get("id")).first():
            s.add(AlertRecord(
                alert_uuid=alert.get("id"), timestamp=alert.get("timestamp"),
                severity=alert.get("severity"), alert_type=alert.get("type"),
                src_ip=alert.get("src_ip"), message=alert.get("message"),
                details=json.dumps(alert.get("details", {})),
            ))
            s.commit()


# ── Read helpers ───────────────────────────────────────────────────────────────

def get_recent_alerts(limit: int = 100) -> List[dict]:
    with Session(engine) as s:
        rows = s.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(limit).all()
        return [{"id":r.alert_uuid,"timestamp":r.timestamp,"severity":r.severity,
                 "type":r.alert_type,"src_ip":r.src_ip,"message":r.message,
                 "details":json.loads(r.details or "{}")} for r in rows]


def get_all_devices() -> List[dict]:
    with Session(engine) as s:
        rows = s.query(DeviceRecord).all()
        return [{"ip":r.ip,"mac":r.mac,"hostname":r.hostname,"vendor":r.vendor,
                 "os_guess":r.os_guess,"open_ports":json.loads(r.open_ports or "[]"),
                 "first_seen":r.first_seen,"last_seen":r.last_seen} for r in rows]


def get_packet_count() -> int:
    with Session(engine) as s:
        return s.query(PacketLog).count()
