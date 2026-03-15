"""Structured JSON logging configuration."""

import logging
import sys

from src.core.config import settings


def configure_logging() -> None:
    """Configure root logger with JSON format for structured logs (event_type, phase, scan_id)."""
    try:
        from pythonjsonlogger import jsonlogger

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(jsonlogger.JsonFormatter(timestamp=True))
        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    except ImportError:
        logging.basicConfig(
            level=getattr(logging, settings.log_level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
