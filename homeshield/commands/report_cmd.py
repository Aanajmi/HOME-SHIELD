"""Report command — generates HTML report from diff or run data.

Usage:
    homeshield report --diff outputs/diff.json --out reports/before_after.html
    homeshield report --run outputs/baseline/run.json --out reports/baseline.html
"""

from homeshield.report.html_report import generate_diff_report, generate_single_run_report
from homeshield.utils.logging_config import get_logger
from homeshield.utils.output import load_json

logger = get_logger("commands.report_cmd")


def execute_report(
    diff_path: str = None,
    run_path: str = None,
    output_path: str = "reports/report.html",
) -> str:
    """Execute report generation.

    Args:
        diff_path: Path to diff.json for comparison report.
        run_path: Path to run.json for single-run report.
        output_path: Path for output HTML file.

    Returns:
        Path of the generated HTML file.

    Raises:
        ValueError: If neither diff_path nor run_path is provided.
    """
    logger.info("=" * 60)
    logger.info("REPORT START")
    logger.info("=" * 60)

    if not diff_path and not run_path:
        msg = "Either --diff or --run must be provided"
        logger.error(msg)
        raise ValueError(msg)

    if diff_path:
        try:
            diff_data = load_json(diff_path)
            result_path = generate_diff_report(diff_data, output_path)
            logger.info("Diff report generated: %s", result_path)
        except Exception as exc:
            logger.error("Failed to generate diff report: %s", exc)
            raise
    else:
        try:
            run_data = load_json(run_path)
            result_path = generate_single_run_report(run_data, output_path)
            logger.info("Single-run report generated: %s", result_path)
        except Exception as exc:
            logger.error("Failed to generate single-run report: %s", exc)
            raise

    logger.info("=" * 60)
    logger.info("REPORT COMPLETE: %s", result_path)
    logger.info("=" * 60)

    return result_path
