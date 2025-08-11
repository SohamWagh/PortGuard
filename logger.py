# logger.py
import logging
from logging.handlers import RotatingFileHandler
import sys

logger = None

def setup_logger(log_file, log_level="INFO", max_bytes=1048576, backup_count=3):
    """
    Set up a rotating logger with the specified parameters.
    """
    global logger
    logger = logging.getLogger("SecurityMonitor")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', "%Y-%m-%d %H:%M:%S")

    handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Also log to console
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

def log_event(message, level="INFO"):
    """
    Log an event at the specified level.
    """
    if logger is None:
        raise Exception("Logger not initialized. Call setup_logger first.")
    if level == "INFO":
        logger.info(message)
    elif level == "WARNING":
        logger.warning(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "CRITICAL":
        logger.critical(message)
    else:
        logger.info(message)

