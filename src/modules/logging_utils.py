"""
SafeNest Logging Utilities

Provides structured logging with JSON formatting for easy parsing and monitoring.
Supports multiple log levels and destinations for security event tracking.
"""

import logging
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Outputs logs in JSON format for easy parsing by log analysis tools.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON string."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra fields passed to logger
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        return json.dumps(log_data)


class SecurityLogger:
    """
    Security-focused logger for SafeNest system.

    Provides methods for logging security events with proper severity levels
    and structured data for automated analysis.
    """

    def __init__(self, name: str, log_file: Optional[str] = None, console: bool = True):
        """
        Initialize security logger.

        Args:
            name: Logger name (typically module name)
            log_file: Path to log file (None for no file logging)
            console: Whether to log to console
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()  # Clear any existing handlers

        # JSON formatter for structured logs
        json_formatter = JSONFormatter()

        # Console handler with color-coded standard format
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)

        # File handler with JSON format
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(json_formatter)
            self.logger.addHandler(file_handler)

    def _log_with_extra(self, level: int, message: str, extra_data: Optional[Dict[str, Any]] = None):
        try:
            if extra_data:
                self.logger.log(level, message, extra={"extra_data": extra_data})
            else:
                self.logger.log(level, message)
        except OSError:
            pass

    def info(self, message: str, **kwargs):
        """Log informational message."""
        self._log_with_extra(logging.INFO, message, kwargs or None)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log_with_extra(logging.WARNING, message, kwargs or None)

    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log_with_extra(logging.ERROR, message, kwargs or None)

    def critical(self, message: str, **kwargs):
        """Log critical security event."""
        self._log_with_extra(logging.CRITICAL, message, kwargs or None)

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log_with_extra(logging.DEBUG, message, kwargs or None)

    def security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """
        Log a security event with structured data.

        Args:
            event_type: Type of security event (e.g., "DOS_DETECTED", "UNAUTHORIZED_ACCESS")
            severity: Severity level ("INFO", "WARN", "CRITICAL")
            details: Dictionary with event details
        """
        log_data = {
            "event_type": event_type,
            "severity": severity,
            **details
        }

        message = f"Security Event: {event_type}"

        if severity == "CRITICAL":
            self._log_with_extra(logging.CRITICAL, message, log_data)
        elif severity == "WARN":
            self._log_with_extra(logging.WARNING, message, log_data)
        else:
            self._log_with_extra(logging.INFO, message, log_data)


def get_logger(name: str, log_file: Optional[str] = None, console: bool = True) -> SecurityLogger:
    """
    Factory function to create a SecurityLogger instance.

    Args:
        name: Logger name
        log_file: Path to log file
        console: Whether to enable console logging

    Returns:
        SecurityLogger instance
    """
    return SecurityLogger(name, log_file, console)
