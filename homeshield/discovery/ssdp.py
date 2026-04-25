"""SSDP discovery module — sends M-SEARCH and collects responder IPs.

Protocol: UDP multicast to 239.255.255.250:1900
Probe: M-SEARCH request with ST: ssdp:all, MX: 2
"""

import socket
import struct
import time
from typing import Dict, List, Optional, Set, Tuple

from homeshield.utils.logging_config import get_logger

logger = get_logger("discovery.ssdp")

SSDP_MULTICAST_ADDR = "239.255.255.250"
SSDP_PORT = 1900

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def _parse_ssdp_headers(data: bytes) -> Dict[str, str]:
    """Parse SSDP response headers.

    Args:
        data: Raw response bytes.

    Returns:
        Dictionary of header name -> value.
    """
    headers = {}
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        for line in lines[1:]:  # skip status line
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().upper()] = value.strip()
    except Exception as exc:
        logger.debug("Failed to parse SSDP headers: %s", exc)
    return headers


def run_ssdp_discovery(
    interface_ip: Optional[str] = None,
    listen_seconds: float = 4.0,
    rounds: int = 1,
    interval: float = 10.0,
) -> Dict[str, any]:
    """Run SSDP discovery for multiple rounds.

    Args:
        interface_ip: Local IP to bind for multicast. None for default.
        listen_seconds: Seconds to listen for responses per round.
        rounds: Number of discovery rounds.
        interval: Seconds between rounds.

    Returns:
        Dictionary with 'unique_responders', 'per_round', and 'headers'.
    """
    logger.info(
        "Starting SSDP discovery: interface_ip=%s, listen=%ss, rounds=%d, interval=%ss",
        interface_ip, listen_seconds, rounds, interval,
    )

    per_round: Dict[str, List[str]] = {}
    all_responders: Set[str] = set()
    all_headers: Dict[str, Dict[str, str]] = {}

    for round_num in range(1, rounds + 1):
        logger.info("SSDP round %d/%d", round_num, rounds)
        round_ips, round_headers = _send_and_listen(interface_ip, listen_seconds)
        sorted_ips = sorted(round_ips)
        per_round[str(round_num)] = sorted_ips
        all_responders.update(round_ips)

        for ip, hdrs in round_headers.items():
            if ip not in all_headers:
                all_headers[ip] = hdrs

        logger.info("SSDP round %d: %d responders found", round_num, len(round_ips))

        if round_num < rounds:
            logger.debug("Waiting %ss before next round", interval)
            time.sleep(interval)

    result = {
        "unique_responders": sorted(all_responders),
        "per_round": per_round,
        "headers": all_headers,
    }
    logger.info("SSDP discovery complete: %d unique responders", len(all_responders))
    return result


def _send_and_listen(
    interface_ip: Optional[str],
    listen_seconds: float,
) -> Tuple[Set[str], Dict[str, Dict[str, str]]]:
    """Send SSDP M-SEARCH and listen for responses.

    Args:
        interface_ip: Interface IP for multicast binding.
        listen_seconds: How long to listen.

    Returns:
        Tuple of (set of responder IPs, dict of IP->headers).
    """
    responders: Set[str] = set()
    headers_map: Dict[str, Dict[str, str]] = {}
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass

        # Bind to any available port (not 1900 — we are sending M-SEARCH, not listening for NOTIFY)
        sock.bind(("", 0))

        # Set outgoing multicast interface
        if interface_ip:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(interface_ip),
            )

        # Set TTL
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # Send the M-SEARCH
        sock.sendto(SSDP_MSEARCH.encode("utf-8"), (SSDP_MULTICAST_ADDR, SSDP_PORT))
        logger.debug("SSDP M-SEARCH sent to %s:%d", SSDP_MULTICAST_ADDR, SSDP_PORT)

        # Listen for unicast responses
        sock.settimeout(0.5)
        deadline = time.monotonic() + listen_seconds

        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                responders.add(src_ip)
                hdrs = _parse_ssdp_headers(data)
                if hdrs:
                    headers_map[src_ip] = {
                        "SERVER": hdrs.get("SERVER", ""),
                        "USN": hdrs.get("USN", ""),
                        "ST": hdrs.get("ST", ""),
                        "LOCATION": hdrs.get("LOCATION", ""),
                    }
                logger.debug("SSDP response from %s (%d bytes)", src_ip, len(data))
            except socket.timeout:
                continue
            except OSError as exc:
                logger.warning("Socket error during SSDP listen: %s", exc)
                break

    except OSError as exc:
        logger.error("SSDP socket setup failed: %s", exc)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return responders, headers_map
