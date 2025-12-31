from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Dict, Any


def setup_logging(cfg: Dict[str, Any]) -> None:
    log_cfg = cfg.get("logging", {})
    level = log_cfg.get("level", "INFO").upper()
    logfile = log_cfg.get("file", "output/pipeline.log")

    os.makedirs(os.path.dirname(logfile), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Rotating file handler (SOC-friendly)
    fh = RotatingFileHandler(logfile, maxBytes=2_000_000, backupCount=3)
    fh.setLevel(level)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

