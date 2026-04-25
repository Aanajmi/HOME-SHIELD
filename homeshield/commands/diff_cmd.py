"""Diff command — compares two run.json files and computes exposure changes.

Usage:
    homeshield diff --before outputs/baseline/run.json --after outputs/hardened/run.json --out outputs/diff.json
"""

from typing import Any, Dict

from homeshield.diff.engine import compute_diff
from homeshield.utils.logging_config import get_logger
from homeshield.utils.output import load_json, write_json

logger = get_logger("commands.diff_cmd")


def execute_diff(
    before_path: str,
    after_path: str,
    output_path: str = "outputs/diff.json",
) -> Dict[str, Any]:
    """Execute diff comparison between two runs.

    Args:
        before_path: Path to baseline run.json.
        after_path: Path to hardened run.json.
        output_path: Path for output diff.json.

    Returns:
        Diff data structure.
    """
    logger.info("=" * 60)
    logger.info("DIFF START: before=%s, after=%s", before_path, after_path)
    logger.info("=" * 60)

    try:
        before_data = load_json(before_path)
        logger.info("Loaded before run: %s", before_data.get("label", "unknown"))
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Failed to load before run.json: %s", exc)
        raise

    try:
        after_data = load_json(after_path)
        logger.info("Loaded after run: %s", after_data.get("label", "unknown"))
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Failed to load after run.json: %s", exc)
        raise

    try:
        diff_data = compute_diff(before_data, after_data)
    except Exception as exc:
        logger.error("Diff computation failed: %s", exc)
        raise

    try:
        write_json(diff_data, output_path)
        logger.info("Diff output written: %s", output_path)
    except Exception as exc:
        logger.error("Failed to write diff output: %s", exc)
        raise

    logger.info("=" * 60)
    logger.info("DIFF COMPLETE: %s", output_path)
    logger.info("=" * 60)

    return diff_data
