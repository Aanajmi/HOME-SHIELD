"""Measure command — runs discovery + reachability and writes structured outputs.

Usage:
    homeshield measure --label baseline_iot_run1 --vantage iot --iface en0 \\
        --rounds 5 --interval 10 --listen 4 --ports 80,443,554,445
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from homeshield.discovery.mdns import run_mdns_discovery
from homeshield.discovery.ssdp import run_ssdp_discovery
from homeshield.reachability.tcp_check import run_reachability_checks, DEFAULT_PORTS
from homeshield.utils.logging_config import get_logger
from homeshield.utils.network import get_interface_ip, get_default_ip
from homeshield.utils.output import ensure_directory, write_json, write_csv

logger = get_logger("commands.measure")


def execute_measure(
    label: str,
    vantage: str = "default",
    iface: Optional[str] = None,
    rounds: int = 3,
    interval: float = 10.0,
    listen: float = 4.0,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    workers: int = 10,
    output_dir: str = "outputs",
) -> Dict[str, Any]:
    """Execute a full measurement run: discovery + reachability.

    Args:
        label: Run label for output directory naming.
        vantage: Vantage point description (e.g., 'iot', 'guest', 'trusted').
        iface: Network interface name (e.g., 'en0', 'eth0').
        rounds: Number of discovery rounds.
        interval: Seconds between rounds.
        listen: Listen window in seconds per round.
        ports: List of TCP ports to check.
        timeout: TCP connect timeout in seconds.
        workers: Number of concurrent reachability workers.
        output_dir: Base output directory.

    Returns:
        Complete run.json data structure.
    """
    logger.info("=" * 60)
    logger.info("MEASURE START: label=%s, vantage=%s", label, vantage)
    logger.info("=" * 60)

    if ports is None:
        ports = DEFAULT_PORTS

    # Resolve interface IP
    interface_ip = None
    if iface:
        interface_ip = get_interface_ip(iface)
        if interface_ip:
            logger.info("Interface %s resolved to IP %s", iface, interface_ip)
        else:
            logger.warning("Could not resolve IP for interface %s — trying default route", iface)
            interface_ip = get_default_ip()
            if interface_ip:
                logger.info("Using default route IP: %s", interface_ip)
    else:
        interface_ip = get_default_ip()
        if interface_ip:
            logger.info("No interface specified — using default route IP: %s", interface_ip)

    # Phase 1: Discovery
    logger.info("Phase 1: Running discovery probes...")

    try:
        mdns_results = run_mdns_discovery(
            interface_ip=interface_ip,
            listen_seconds=listen,
            rounds=rounds,
            interval=interval,
        )
    except Exception as exc:
        logger.error("mDNS discovery failed: %s", exc)
        mdns_results = {"unique_responders": [], "per_round": {}}

    try:
        ssdp_results = run_ssdp_discovery(
            interface_ip=interface_ip,
            listen_seconds=listen,
            rounds=rounds,
            interval=interval,
        )
    except Exception as exc:
        logger.error("SSDP discovery failed: %s", exc)
        ssdp_results = {"unique_responders": [], "per_round": {}, "headers": {}}

    # Collect all discovered IPs for reachability
    all_discovered_ips = sorted(set(
        mdns_results.get("unique_responders", [])
        + ssdp_results.get("unique_responders", [])
    ))
    logger.info("Total unique discovered IPs: %d", len(all_discovered_ips))

    # Phase 2: Reachability
    logger.info("Phase 2: Running TCP reachability checks...")

    try:
        reachability_results = run_reachability_checks(
            target_ips=all_discovered_ips,
            ports=ports,
            timeout=timeout,
            workers=workers,
        )
    except Exception as exc:
        logger.error("Reachability checks failed: %s", exc)
        reachability_results = {"ports_tested": sorted(ports), "results": []}

    # Phase 3: Write outputs
    logger.info("Phase 3: Writing output artifacts...")

    run_dir = os.path.join(output_dir, label)
    ensure_directory(run_dir)

    timestamp_utc = datetime.now(timezone.utc).isoformat()

    run_data = {
        "label": label,
        "timestamp_utc": timestamp_utc,
        "vantage": vantage,
        "host": {
            "interface": iface or "default",
            "ip": interface_ip or "unknown",
        },
        "schedule": {
            "rounds": rounds,
            "interval": interval,
            "listen": listen,
        },
        "discovery": {
            "mdns": mdns_results,
            "ssdp": ssdp_results,
        },
        "reachability": reachability_results,
        "artifacts": {
            "run_json": os.path.join(run_dir, "run.json"),
            "discovery_csv": os.path.join(run_dir, "discovery.csv"),
            "reachability_csv": os.path.join(run_dir, "reachability.csv"),
        },
    }

    # Write run.json
    try:
        write_json(run_data, os.path.join(run_dir, "run.json"))
    except Exception as exc:
        logger.error("Failed to write run.json: %s", exc)

    # Write discovery.csv
    try:
        discovery_rows = _build_discovery_csv_rows(mdns_results, ssdp_results)
        write_csv(
            discovery_rows,
            os.path.join(run_dir, "discovery.csv"),
            fieldnames=["protocol", "round", "responder_ip"],
        )
    except Exception as exc:
        logger.error("Failed to write discovery.csv: %s", exc)

    # Write reachability.csv
    try:
        reach_rows = reachability_results.get("results", [])
        write_csv(
            reach_rows,
            os.path.join(run_dir, "reachability.csv"),
            fieldnames=["dst_ip", "port", "state", "rtt_ms", "service"],
        )
    except Exception as exc:
        logger.error("Failed to write reachability.csv: %s", exc)

    logger.info("=" * 60)
    logger.info("MEASURE COMPLETE: outputs in %s", run_dir)
    logger.info("=" * 60)

    return run_data


def _build_discovery_csv_rows(
    mdns_results: Dict[str, Any],
    ssdp_results: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Build flat CSV rows from discovery results.

    Args:
        mdns_results: mDNS discovery results.
        ssdp_results: SSDP discovery results.

    Returns:
        List of row dictionaries.
    """
    rows = []

    for round_num, ips in sorted(mdns_results.get("per_round", {}).items()):
        for ip in ips:
            rows.append({
                "protocol": "mDNS",
                "round": round_num,
                "responder_ip": ip,
            })

    for round_num, ips in sorted(ssdp_results.get("per_round", {}).items()):
        for ip in ips:
            rows.append({
                "protocol": "SSDP",
                "round": round_num,
                "responder_ip": ip,
            })

    return rows
