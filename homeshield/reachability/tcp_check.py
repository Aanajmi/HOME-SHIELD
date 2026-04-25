"""TCP reachability module — connect checks on configurable port list.

Performs safe, non-intrusive TCP connect scans to determine port state:
- OPEN: TCP handshake completed
- CLOSED: Connection refused (RST received)
- TIMEOUT: No response within timeout period
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from homeshield.utils.logging_config import get_logger

logger = get_logger("reachability.tcp_check")

# Default port list per specification
DEFAULT_PORTS = [80, 443, 554, 445, 1883, 8080, 8443, 8883]

# Port description map for reporting
PORT_DESCRIPTIONS = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    445: "SMB",
    1883: "MQTT",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
}


def check_single_port(
    dst_ip: str,
    port: int,
    timeout: float = 1.0,
) -> Dict[str, any]:
    """Check TCP reachability of a single IP:port.

    Args:
        dst_ip: Destination IP address.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        Dictionary with dst_ip, port, state, rtt_ms.
    """
    result = {
        "dst_ip": dst_ip,
        "port": port,
        "state": "TIMEOUT",
        "rtt_ms": None,
        "service": PORT_DESCRIPTIONS.get(port, "unknown"),
    }

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        error_code = sock.connect_ex((dst_ip, port))
        elapsed = (time.monotonic() - start) * 1000  # ms

        if error_code == 0:
            result["state"] = "OPEN"
            result["rtt_ms"] = round(elapsed, 2)
            logger.debug("OPEN %s:%d (%.2fms)", dst_ip, port, elapsed)
        elif error_code == 111 or error_code == 61:
            # 111 = ECONNREFUSED (Linux), 61 = ECONNREFUSED (macOS)
            result["state"] = "CLOSED"
            result["rtt_ms"] = round(elapsed, 2)
            logger.debug("CLOSED %s:%d (%.2fms)", dst_ip, port, elapsed)
        else:
            result["state"] = "TIMEOUT"
            logger.debug("TIMEOUT %s:%d (error_code=%d)", dst_ip, port, error_code)

    except socket.timeout:
        result["state"] = "TIMEOUT"
        logger.debug("TIMEOUT %s:%d (socket.timeout)", dst_ip, port)
    except OSError as exc:
        if exc.errno in (111, 61):  # Connection refused
            result["state"] = "CLOSED"
        else:
            result["state"] = "TIMEOUT"
        logger.debug("OSError %s:%d: %s", dst_ip, port, exc)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return result


def run_reachability_checks(
    target_ips: List[str],
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    workers: int = 10,
) -> Dict[str, any]:
    """Run TCP reachability checks against a list of IPs and ports.

    Args:
        target_ips: List of IP addresses to check.
        ports: List of TCP ports to check. Defaults to DEFAULT_PORTS.
        timeout: TCP connect timeout in seconds.
        workers: Number of concurrent worker threads.

    Returns:
        Dictionary with 'ports_tested' and 'results' (sorted list of check results).
    """
    if ports is None:
        ports = DEFAULT_PORTS

    sorted_ips = sorted(target_ips)
    sorted_ports = sorted(ports)

    logger.info(
        "Starting reachability checks: %d IPs x %d ports = %d checks (workers=%d, timeout=%ss)",
        len(sorted_ips), len(sorted_ports),
        len(sorted_ips) * len(sorted_ports),
        workers, timeout,
    )

    results: List[Dict[str, any]] = []

    if not sorted_ips:
        logger.warning("No target IPs provided for reachability checks")
        return {"ports_tested": sorted_ports, "results": []}

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for ip in sorted_ips:
                for port in sorted_ports:
                    future = executor.submit(check_single_port, ip, port, timeout)
                    futures[future] = (ip, port)

            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    result = future.result(timeout=timeout + 5)
                    results.append(result)
                except Exception as exc:
                    logger.error("Check failed for %s:%d: %s", ip, port, exc)
                    results.append({
                        "dst_ip": ip,
                        "port": port,
                        "state": "TIMEOUT",
                        "rtt_ms": None,
                        "service": PORT_DESCRIPTIONS.get(port, "unknown"),
                    })
    except Exception as exc:
        logger.error("Thread pool execution failed: %s", exc)

    # Sort results for deterministic output
    results.sort(key=lambda r: (r["dst_ip"], r["port"]))

    open_count = sum(1 for r in results if r["state"] == "OPEN")
    logger.info(
        "Reachability checks complete: %d total, %d OPEN, %d CLOSED, %d TIMEOUT",
        len(results), open_count,
        sum(1 for r in results if r["state"] == "CLOSED"),
        sum(1 for r in results if r["state"] == "TIMEOUT"),
    )

    return {"ports_tested": sorted_ports, "results": results}
