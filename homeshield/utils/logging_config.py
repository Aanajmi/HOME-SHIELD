"""Centralized logging configuration for HomeShield.

All modules use a single log file: homeshield.log
"""

import logging
import os
from pathlib import Path


_LOGGER_INITIALIZED = False


def setup_logging(log_dir: str = None, level: int = logging.DEBUG) -> logging.Logger:
    """Configure and return the root HomeShield logger.

    Args:
        log_dir: Directory for the log file. Defaults to current working directory.
        level: Logging level. Defaults to DEBUG.

    Returns:
        Configured logger instance.
    """
    global _LOGGER_INITIALIZED

    logger = logging.getLogger("homeshield")

    if _LOGGER_INITIALIZED:
        return logger

    logger.setLevel(level)

    if log_dir is None:
        log_dir = os.getcwd()

    log_path = Path(log_dir) / "homeshield.log"

    file_handler = logging.FileHandler(str(log_path), mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    file_format = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s.%(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_format = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    file_handler.setFormatter(file_format)
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    _LOGGER_INITIALIZED = True
    logger.info("HomeShield logging initialized — log file: %s", log_path)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the homeshield namespace.

    Args:
        name: Logger name (will be prefixed with 'homeshield.').

    Returns:
        Child logger instance.
    """
    return logging.getLogger(f"homeshield.{name}")
