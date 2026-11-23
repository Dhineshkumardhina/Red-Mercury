"""Structured logging setup for Red Mercury."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Regex patterns to scrub credentials from console and JSON log records
LOG_SCRUB_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48}|sk_live_[0-9a-zA-Z]{24})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"), "[REDACTED_JWT_TOKEN]"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9-_\.]+"), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r'(?i)(password|secret|passwd|token|raw_credential)\s*[:=]\s*["\'](?!\[REDACTED_)([^"\']{4,})["\']'), r'\1="[REDACTED_SECRET]"'),
    (re.compile(r"(postgres|postgresql|mysql|mongodb|redis):\/\/([^:]+):([^@]+)@"), r"\1://\2:[REDACTED_DB_PASSWORD]@"),
]


def scrub_log_message(text: str) -> str:
    """Mask high-entropy secrets and sensitive authentication tokens in log strings."""
    if not text:
        return ""
    for pattern, replacement in LOG_SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class JSONFormatter(logging.Formatter):
    """Format logs as structured JSON strings with secret scrubbing."""

    def format(self, record: logging.LogRecord) -> str:
        raw_msg = record.getMessage()
        clean_msg = scrub_log_message(raw_msg)

        log_record: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": clean_msg,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include custom attributes (e.g., request_id, client_ip)
        for key in ["request_id", "method", "path", "status_code", "duration_ms", "correlation_id"]:
            if hasattr(record, key):
                val = getattr(record, key)
                log_record[key] = scrub_log_message(str(val)) if isinstance(val, str) else val

        if record.exc_info:
            log_record["exception"] = scrub_log_message(self.formatException(record.exc_info))

        return json.dumps(log_record)


class StandardFormatter(logging.Formatter):
    """Clean, human-readable structured console format with secret scrubbing."""

    def format(self, record: logging.LogRecord) -> str:
        req_id = getattr(record, "request_id", "-")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{timestamp}] [{record.levelname:<8}] [{record.name}] [req:{req_id}]"
        clean_msg = scrub_log_message(record.getMessage())
        msg = f"{prefix} {clean_msg}"
        if record.exc_info:
            msg += f"\n{scrub_log_message(self.formatException(record.exc_info))}"
        return msg


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_dir: Optional[str] = None,
    log_filename: str = "backend.log",
) -> None:
    """Configure root and app loggers with optional secret-scrubbed rotating file output."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to prevent duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    formatter: logging.Formatter = JSONFormatter() if json_format else StandardFormatter()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    effective_log_dir = (log_dir or os.environ.get("REDMERCURY_LOG_DIR") or "").strip()
    if effective_log_dir:
        try:
            dir_path = Path(effective_log_dir)
            dir_path.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                os.chmod(dir_path, 0o700)
            log_file = dir_path / log_filename
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            if os.name == "posix" and log_file.exists():
                os.chmod(log_file, 0o600)
        except Exception:
            # Never fail startup if file logging cannot be initialized
            pass

    # Adjust external loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger instance with the given module name."""
    return logging.getLogger(name)
