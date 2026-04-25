"""PCAP parser module — extracts mDNS/SSDP talkers using tshark.

Optional module: requires tshark to be installed on the system.
Fails gracefully if tshark is not available.
"""

import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from homeshield.utils.logging_config import get_logger

logger = get_logger("pcap.parser")


def is_tshark_available() -> bool:
    """Check if tshark is installed and accessible.

    Returns:
        True if tshark is available on PATH.
    """
    available = shutil.which("tshark") is not None
    if available:
        logger.debug("tshark found on PATH")
    else:
        logger.warning("tshark not found on PATH — PCAP parsing unavailable")
    return available


def get_tshark_version() -> Optional[str]:
    """Get the tshark version string.

    Returns:
        Version string, or None if tshark is not available.
    """
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        first_line = result.stdout.strip().split("\n")[0]
        logger.debug("tshark version: %s", first_line)
        return first_line
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Failed to get tshark version: %s", exc)
        return None


def extract_mdns_talkers(pcap_path: str) -> List[Dict[str, str]]:
    """Extract mDNS talker IPs from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        List of dictionaries with source IP and query info.

    Raises:
        RuntimeError: If tshark is not available or parsing fails.
    """
    if not is_tshark_available():
        raise RuntimeError("tshark is not installed — cannot parse PCAP files")

    logger.info("Extracting mDNS talkers from: %s", pcap_path)

    try:
        result = subprocess.run(
            [
                "tshark",
                "-r", pcap_path,
                "-Y", "mdns",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "dns.qry.name",
                "-e", "dns.resp.name",
                "-E", "header=y",
                "-E", "separator=|",
            ],
            capture_output=True, text=True, timeout=60,
        )

        if result.returncode != 0:
            logger.error("tshark mDNS extraction failed: %s", result.stderr.strip())
            raise RuntimeError(f"tshark failed: {result.stderr.strip()}")

        talkers = _parse_tshark_output(result.stdout, "mdns")
        logger.info("Extracted %d mDNS entries from PCAP", len(talkers))
        return talkers

    except subprocess.TimeoutExpired:
        logger.error("tshark timed out processing: %s", pcap_path)
        raise RuntimeError("tshark timed out processing PCAP file")
    except FileNotFoundError:
        raise RuntimeError("tshark not found — please install Wireshark/tshark")


def extract_ssdp_talkers(pcap_path: str) -> List[Dict[str, str]]:
    """Extract SSDP talker IPs from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        List of dictionaries with source IP and SSDP info.

    Raises:
        RuntimeError: If tshark is not available or parsing fails.
    """
    if not is_tshark_available():
        raise RuntimeError("tshark is not installed — cannot parse PCAP files")

    logger.info("Extracting SSDP talkers from: %s", pcap_path)

    try:
        result = subprocess.run(
            [
                "tshark",
                "-r", pcap_path,
                "-Y", "ssdp",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "http.server",
                "-e", "http.location",
                "-E", "header=y",
                "-E", "separator=|",
            ],
            capture_output=True, text=True, timeout=60,
        )

        if result.returncode != 0:
            logger.error("tshark SSDP extraction failed: %s", result.stderr.strip())
            raise RuntimeError(f"tshark failed: {result.stderr.strip()}")

        talkers = _parse_tshark_output(result.stdout, "ssdp")
        logger.info("Extracted %d SSDP entries from PCAP", len(talkers))
        return talkers

    except subprocess.TimeoutExpired:
        logger.error("tshark timed out processing: %s", pcap_path)
        raise RuntimeError("tshark timed out processing PCAP file")
    except FileNotFoundError:
        raise RuntimeError("tshark not found — please install Wireshark/tshark")


def parse_pcap(pcap_path: str) -> Dict[str, Any]:
    """Parse a PCAP file and extract all mDNS and SSDP talkers.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        Dictionary with mdns_talkers, ssdp_talkers, and unique IPs.
    """
    logger.info("Parsing PCAP: %s", pcap_path)

    mdns_talkers = []
    ssdp_talkers = []

    try:
        mdns_talkers = extract_mdns_talkers(pcap_path)
    except RuntimeError as exc:
        logger.warning("mDNS extraction failed: %s", exc)

    try:
        ssdp_talkers = extract_ssdp_talkers(pcap_path)
    except RuntimeError as exc:
        logger.warning("SSDP extraction failed: %s", exc)

    # Collect unique IPs
    all_ips = set()
    for entry in mdns_talkers:
        if entry.get("ip_src"):
            all_ips.add(entry["ip_src"])
    for entry in ssdp_talkers:
        if entry.get("ip_src"):
            all_ips.add(entry["ip_src"])

    result = {
        "pcap_path": pcap_path,
        "mdns_talkers": mdns_talkers,
        "ssdp_talkers": ssdp_talkers,
        "unique_ips": sorted(all_ips),
        "mdns_unique_ips": sorted({e["ip_src"] for e in mdns_talkers if e.get("ip_src")}),
        "ssdp_unique_ips": sorted({e["ip_src"] for e in ssdp_talkers if e.get("ip_src")}),
    }

    logger.info(
        "PCAP parse complete: %d mDNS entries, %d SSDP entries, %d unique IPs",
        len(mdns_talkers), len(ssdp_talkers), len(all_ips),
    )

    return result


def _parse_tshark_output(output: str, protocol: str) -> List[Dict[str, str]]:
    """Parse tshark tabular output into list of dictionaries.

    Args:
        output: Raw tshark stdout.
        protocol: Protocol name for logging.

    Returns:
        List of parsed row dictionaries.
    """
    lines = output.strip().split("\n")
    if len(lines) < 2:
        return []

    headers = [h.strip().replace(".", "_") for h in lines[0].split("|")]
    entries = []

    for line in lines[1:]:
        fields = line.split("|")
        if len(fields) != len(headers):
            continue
        entry = {headers[i]: fields[i].strip() for i in range(len(headers))}
        entries.append(entry)

    return entries
