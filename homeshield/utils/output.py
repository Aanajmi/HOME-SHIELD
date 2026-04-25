"""Output writing utilities for HomeShield — JSON and CSV generation."""

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from homeshield.utils.logging_config import get_logger

logger = get_logger("utils.output")


def ensure_directory(path: str) -> str:
    """Create directory if it does not exist.

    Args:
        path: Directory path to create.

    Returns:
        Absolute path of the directory.
    """
    abs_path = os.path.abspath(path)
    try:
        os.makedirs(abs_path, exist_ok=True)
        logger.debug("Directory ensured: %s", abs_path)
    except OSError as exc:
        logger.error("Failed to create directory %s: %s", abs_path, exc)
        raise
    return abs_path


def write_json(data: Dict[str, Any], filepath: str) -> str:
    """Write data to a JSON file with pretty formatting.

    Args:
        data: Dictionary to serialize.
        filepath: Output file path.

    Returns:
        Absolute path of the written file.
    """
    abs_path = os.path.abspath(filepath)
    try:
        ensure_directory(os.path.dirname(abs_path))
        with open(abs_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=False, ensure_ascii=False)
            fh.write("\n")
        logger.info("JSON written: %s (%d bytes)", abs_path, os.path.getsize(abs_path))
    except (OSError, TypeError, ValueError) as exc:
        logger.error("Failed to write JSON to %s: %s", abs_path, exc)
        raise
    return abs_path


def write_csv(rows: List[Dict[str, Any]], filepath: str, fieldnames: List[str]) -> str:
    """Write rows to a CSV file.

    Args:
        rows: List of dictionaries to write.
        filepath: Output file path.
        fieldnames: Column names for the CSV header.

    Returns:
        Absolute path of the written file.
    """
    abs_path = os.path.abspath(filepath)
    try:
        ensure_directory(os.path.dirname(abs_path))
        with open(abs_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        logger.info("CSV written: %s (%d rows)", abs_path, len(rows))
    except (OSError, ValueError) as exc:
        logger.error("Failed to write CSV to %s: %s", abs_path, exc)
        raise
    return abs_path


def load_json(filepath: str) -> Dict[str, Any]:
    """Load and parse a JSON file.

    Args:
        filepath: Path to JSON file.

    Returns:
        Parsed dictionary.

    Raises:
        FileNotFoundError: If file does not exist.
        json.JSONDecodeError: If file is not valid JSON.
    """
    abs_path = os.path.abspath(filepath)
    try:
        with open(abs_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        logger.info("JSON loaded: %s", abs_path)
        return data
    except FileNotFoundError:
        logger.error("File not found: %s", abs_path)
        raise
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", abs_path, exc)
        raise
