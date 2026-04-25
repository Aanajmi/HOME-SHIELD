"""mDNS discovery module — sends PTR queries and collects responder IPs.

Protocol: UDP multicast to 224.0.0.251:5353
Probe: DNS PTR query for _services._dns-sd._udp.local
"""

import platform
import socket
import struct
import time
from typing import Dict, List, Optional, Set

from homeshield.utils.logging_config import get_logger

logger = get_logger("discovery.mdns")

MDNS_MULTICAST_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# DNS PTR query for _services._dns-sd._udp.local
# Constructed as a standard DNS query packet
MDNS_QUERY_NAME = "_services._dns-sd._udp.local"


def _build_mdns_query() -> bytes:
    """Build a DNS PTR query packet for service enumeration.

    Returns:
        Raw bytes of the DNS query.
    """
    # DNS header: ID=0, Flags=0 (standard query), QDCOUNT=1
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)

    # Encode the query name
    question = b""
    for label in MDNS_QUERY_NAME.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"  # null terminator

    # QTYPE=PTR (12), QCLASS=IN (1)
    question += struct.pack("!HH", 12, 1)

    return header + question


def run_mdns_discovery(
    interface_ip: Optional[str] = None,
    listen_seconds: float = 4.0,
    rounds: int = 1,
    interval: float = 10.0,
) -> Dict[str, any]:
    """Run mDNS discovery for multiple rounds.

    Args:
        interface_ip: Local IP to bind for multicast. None for default.
        listen_seconds: Seconds to listen for responses per round.
        rounds: Number of discovery rounds.
        interval: Seconds between rounds.

    Returns:
        Dictionary with 'unique_responders' (sorted list) and 'per_round' (dict of round->IPs).
    """
    logger.info(
        "Starting mDNS discovery: interface_ip=%s, listen=%ss, rounds=%d, interval=%ss",
        interface_ip, listen_seconds, rounds, interval,
    )

    query_packet = _build_mdns_query()
    per_round: Dict[str, List[str]] = {}
    all_responders: Set[str] = set()

    for round_num in range(1, rounds + 1):
        logger.info("mDNS round %d/%d", round_num, rounds)
        round_ips = _send_and_listen(query_packet, interface_ip, listen_seconds)
        sorted_ips = sorted(round_ips)
        per_round[str(round_num)] = sorted_ips
        all_responders.update(round_ips)
        logger.info("mDNS round %d: %d responders found", round_num, len(round_ips))

        if round_num < rounds:
            logger.debug("Waiting %ss before next round", interval)
            time.sleep(interval)

    result = {
        "unique_responders": sorted(all_responders),
        "per_round": per_round,
    }
    logger.info("mDNS discovery complete: %d unique responders", len(all_responders))
    return result


def _send_and_listen(
    query_packet: bytes,
    interface_ip: Optional[str],
    listen_seconds: float,
) -> Set[str]:
    """Send mDNS query and listen for responses.

    Args:
        query_packet: Raw DNS query bytes.
        interface_ip: Interface IP for multicast binding.
        listen_seconds: How long to listen.

    Returns:
        Set of responder IP addresses.
    """
    responders: Set[str] = set()
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass  # SO_REUSEPORT not available on all platforms

        # Windows requires binding to specific interface IP; Unix binds to ""
        bind_addr = interface_ip if (platform.system() == "Windows" and interface_ip) else ""
        sock.bind((bind_addr, MDNS_PORT))

        # Join multicast group
        if interface_ip:
            mreq = struct.pack(
                "4s4s",
                socket.inet_aton(MDNS_MULTICAST_ADDR),
                socket.inet_aton(interface_ip),
            )
        else:
            mreq = struct.pack(
                "4sI",
                socket.inet_aton(MDNS_MULTICAST_ADDR),
                socket.INADDR_ANY,
            )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Set outgoing multicast interface
        if interface_ip:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(interface_ip),
            )

        # Set TTL
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # Send the query
        sock.sendto(query_packet, (MDNS_MULTICAST_ADDR, MDNS_PORT))
        logger.debug("mDNS query sent to %s:%d", MDNS_MULTICAST_ADDR, MDNS_PORT)

        # Listen for responses
        sock.settimeout(0.5)
        deadline = time.monotonic() + listen_seconds

        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                # Skip our own query reflections if interface_ip matches
                if interface_ip and src_ip == interface_ip:
                    continue
                if _is_mdns_response(data):
                    responders.add(src_ip)
                    logger.debug("mDNS response from %s (%d bytes)", src_ip, len(data))
            except socket.timeout:
                continue
            except OSError as exc:
                logger.warning("Socket error during mDNS listen: %s", exc)
                break

    except OSError as exc:
        logger.error("mDNS socket setup failed: %s", exc)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return responders


def _is_mdns_response(data: bytes) -> bool:
    """Check if a received packet is a DNS response (QR bit set).

    Args:
        data: Raw packet bytes.

    Returns:
        True if packet appears to be a DNS response.
    """
    if len(data) < 12:
        return False
    flags = struct.unpack("!H", data[2:4])[0]
    qr_bit = (flags >> 15) & 1
    return qr_bit == 1
