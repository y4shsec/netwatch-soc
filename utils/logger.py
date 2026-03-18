import logging, os, sys
from logging.handlers import RotatingFileHandler
import config

os.makedirs("logs", exist_ok=True)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(name)s — %(message)s", "%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    fh = RotatingFileHandler(config.LOG_FILE, maxBytes=5*1024*1024, backupCount=3)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger
