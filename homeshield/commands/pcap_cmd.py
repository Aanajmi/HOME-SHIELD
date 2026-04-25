"""PCAP parse command — extracts mDNS/SSDP talkers from PCAP files.

Usage:
    homeshield pcap-parse --pcap evidence/pcaps/capture.pcap
"""

import json
import sys

from homeshield.pcap.parser import parse_pcap, is_tshark_available, get_tshark_version
from homeshield.utils.logging_config import get_logger

logger = get_logger("commands.pcap_cmd")


def execute_pcap_parse(pcap_path: str) -> dict:
    """Execute PCAP parsing.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        Parsed PCAP data.

    Raises:
        RuntimeError: If tshark is not available.
        FileNotFoundError: If PCAP file does not exist.
    """
    logger.info("=" * 60)
    logger.info("PCAP-PARSE START: %s", pcap_path)
    logger.info("=" * 60)

    # Check tshark availability
    if not is_tshark_available():
        msg = (
            "tshark is not installed or not found on PATH.\n"
            "Install Wireshark/tshark to use PCAP parsing:\n"
            "  macOS:  brew install wireshark\n"
            "  Linux:  sudo apt install tshark\n"
        )
        logger.error(msg)
        raise RuntimeError(msg)

    version = get_tshark_version()
    if version:
        logger.info("Using %s", version)

    import os
    if not os.path.isfile(pcap_path):
        msg = f"PCAP file not found: {pcap_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)

    try:
        result = parse_pcap(pcap_path)
    except Exception as exc:
        logger.error("PCAP parsing failed: %s", exc)
        raise

    # Print structured output to stdout
    print(json.dumps(result, indent=2))

    logger.info("=" * 60)
    logger.info("PCAP-PARSE COMPLETE: %d unique IPs found", len(result.get("unique_ips", [])))
    logger.info("=" * 60)

    return result
