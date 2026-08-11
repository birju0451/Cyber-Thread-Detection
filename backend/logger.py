"""
backend/logger.py
==================
Structured, colored logging for the ABTD system.
Writes to both console (colorized) and a rotating file.
"""

import sys
import logging
import logging.handlers
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config

try:
    import colorlog
    _HAS_COLORLOG = True
except ImportError:
    _HAS_COLORLOG = False


def _setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger   # Already configured

    logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    fmt = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # ── Console handler (colored) ────────────────────────────────────
    if _HAS_COLORLOG:
        color_fmt = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)-8s]%(reset)s %(cyan)s%(name)s%(reset)s — %(message)s",
            datefmt=datefmt,
            log_colors={
                "DEBUG"   : "white",
                "INFO"    : "green",
                "WARNING" : "yellow",
                "ERROR"   : "red",
                "CRITICAL": "bold_red",
            },
        )
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(color_fmt)
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(fmt, datefmt))

    logger.addHandler(console_handler)

    # ── Rotating file handler ────────────────────────────────────────
    try:
        config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter(fmt, datefmt))
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not set up file logging: {e}")

    logger.propagate = False
    return logger


# Public loggers
log_system = _setup_logger("abtd.system")
log_engine = _setup_logger("abtd.engine")
log_agent  = _setup_logger("abtd.agent")
log_api    = _setup_logger("abtd.api")
