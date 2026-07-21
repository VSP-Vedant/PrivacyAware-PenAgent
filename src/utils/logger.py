"""Structured JSON logging configuration for the project."""

import json
import logging
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a JSON string."""
        log_obj: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        # Include any extra attributes passed via the 'extra' dict
        if hasattr(record, "extra_data"):
            log_obj["data"] = getattr(record, "extra_data")

        # Include exception traceback if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logger(
    name: str, log_file: str | None = None, level: int = logging.INFO
) -> logging.Logger:
    """Set up and return a logger with JSON formatting."""
    logger = logging.getLogger(name)

    # Avoid adding multiple handlers if the logger is already set up
    if logger.handlers:
        return logger

    logger.setLevel(level)
    formatter = JSONFormatter()

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
