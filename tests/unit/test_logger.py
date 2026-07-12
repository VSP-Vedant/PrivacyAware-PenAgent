"""Unit tests for the structured JSON logger."""

import json
import logging
from src.utils.logger import JSONFormatter, setup_logger

def test_json_formatter() -> None:
    """Verify JSON formatter outputs correctly structured JSON."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="agent_logger",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Task completed successfully.",
        args=(),
        exc_info=None,
    )
    
    # Format the record
    output = formatter.format(record)
    
    # Parse back to dictionary to verify structure
    data = json.loads(output)
    assert data["name"] == "agent_logger"
    assert data["level"] == "INFO"
    assert data["message"] == "Task completed successfully."
    assert "timestamp" in data

def test_json_formatter_with_extra() -> None:
    """Verify extra data is correctly serialized."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="agent_logger",
        level=logging.DEBUG,
        pathname="",
        lineno=0,
        msg="Extracted credentials",
        args=(),
        exc_info=None,
    )
    # Simulate attaching extra data
    record.extra_data = {"user": "admin", "password": "password123"}
    
    output = formatter.format(record)
    data = json.loads(output)
    
    assert data["data"]["user"] == "admin"
    assert data["data"]["password"] == "password123"

def test_setup_logger() -> None:
    """Verify logger setup attaches correct handlers."""
    logger = setup_logger("test_setup_logger")
    assert logger.name == "test_setup_logger"
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    
    # The handler should use our JSONFormatter
    assert isinstance(logger.handlers[0].formatter, JSONFormatter)