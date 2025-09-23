import os
import logging
import json
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

logger = logging.getLogger("__name__")


def configure_logging(
    log_level: str = "INFO", log_json: bool = False, log_dir: Optional[str] = None
) -> None:
    """Configure logging with selectable level and format.

    Args:
        log_level: Logging level ("DEBUG", "INFO", "WARN", "ERROR"). Defaults to "INFO".
        log_json: If True, use JSON log format. Defaults to False.
        log_dir: Directory to save log files. If None, no file logging.

    Raises:
        ValueError: If log_level is invalid.
    """
    valid_levels = {"DEBUG", "INFO", "WARN", "ERROR"}
    log_level = log_level.upper()
    if log_level not in valid_levels:
        raise ValueError(f"Invalid log level: {log_level}. Must be one of {valid_levels}")

    level = getattr(logging, log_level, logging.INFO)

    # JSON formatter
    class JSONFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            log_data = {
                "level": record.levelname,
                "message": record.getMessage(),
                "module": record.module,
                "funcName": record.funcName,
                "lineno": record.lineno,
                "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            }
            return json.dumps(log_data, ensure_ascii=False)

    # Configure handlers
    handlers = []
    if log_json:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(module)s:%(funcName)s:%(lineno)d - %(message)s"
        )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # File handler (if log_dir provided)
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            Path(log_dir) / "lp_importer.log", encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(level=level, handlers=handlers)


def setup_logging() -> None:
    """Setup logging from .env variables.

    Reads LP_LOG_LEVEL and LP_LOG_JSON from .env, defaults to INFO and plain text.
    Logs to ARTIFACTS_DIR/logs/lp_importer.log if ARTIFACTS_DIR is set.

    Raises:
        ValueError: If LP_LOG_LEVEL is invalid.
    """
    load_dotenv(dotenv_path='.env')
    log_level = os.getenv("LP_LOG_LEVEL", "INFO")
    logger.info(f"logging level is: {log_level}")
    log_json = os.getenv("LP_LOG_JSON", "false").lower() == "true"
    log_dir = os.getenv("ARTIFACTS_DIR", "./artifacts") + "/logs"
    configure_logging(log_level, log_json, log_dir)