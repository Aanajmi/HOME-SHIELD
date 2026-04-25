"""Diff and scoring engine — compares before/after runs and computes exposure scores.

Scoring model:
- Start at 100 points
- Subtract for each discovered responder (mDNS/SSDP)
- Subtract more for each OPEN port
- Extra penalty for new OPEN services appearing after hardening
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from homeshield.utils.logging_config import get_logger

logger = get_logger("diff.engine")

# Scoring weights
SCORE_BASE = 100
PENALTY_MDNS_RESPONDER = 2       # per unique mDNS responder
PENALTY_SSDP_RESPONDER = 2       # per unique SSDP responder
PENALTY_OPEN_PORT = 5            # per OPEN port
PENALTY_NEW_OPEN_PORT = 8        # extra penalty for newly OPEN port after hardening


def compute_diff(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Compute diff between two run.json structures.

    Args:
        before: Parsed run.json from baseline run.
        after: Parsed run.json from hardened run.

    Returns:
        Diff dictionary with deltas, scores, and metadata.
    """
    logger.info(
        "Computing diff: before=%s, after=%s",
        before.get("label", "unknown"),
        after.get("label", "unknown"),
    )

    try:
        discovery_delta = _compute_discovery_delta(before, after)
        reachability_delta = _compute_reachability_delta(before, after)
        before_score = _compute_score(before)
        after_score = _compute_score(after, reachability_delta)
        improvement = after_score - before_score

        diff_result = {
            "before_label": before.get("label", "unknown"),
            "after_label": after.get("label", "unknown"),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "discovery_delta": discovery_delta,
            "reachability_delta": reachability_delta,
            "scores": {
                "before": before_score,
                "after": after_score,
                "improvement": improvement,
            },
            "summary": _build_summary(discovery_delta, reachability_delta, before_score, after_score),
        }

        logger.info(
            "Diff computed: before_score=%d, after_score=%d, improvement=%+d",
            before_score, after_score, improvement,
        )
        return diff_result

    except Exception as exc:
        logger.error("Failed to compute diff: %s", exc)
        raise


def _compute_discovery_delta(
    before: Dict[str, Any], after: Dict[str, Any]
) -> Dict[str, Any]:
    """Compute discovery delta between two runs.

    Args:
        before: Baseline run data.
        after: Hardened run data.

    Returns:
        Dictionary with mdns and ssdp added/removed sets.
    """
    before_disc = before.get("discovery", {})
    after_disc = after.get("discovery", {})

    # mDNS delta
    before_mdns = set(before_disc.get("mdns", {}).get("unique_responders", []))
    after_mdns = set(after_disc.get("mdns", {}).get("unique_responders", []))

    # SSDP delta
    before_ssdp = set(before_disc.get("ssdp", {}).get("unique_responders", []))
    after_ssdp = set(after_disc.get("ssdp", {}).get("unique_responders", []))

    delta = {
        "mdns": {
            "added": sorted(after_mdns - before_mdns),
            "removed": sorted(before_mdns - after_mdns),
            "before_count": len(before_mdns),
            "after_count": len(after_mdns),
        },
        "ssdp": {
            "added": sorted(after_ssdp - before_ssdp),
            "removed": sorted(before_ssdp - after_ssdp),
            "before_count": len(before_ssdp),
            "after_count": len(after_ssdp),
        },
    }

    logger.debug(
        "Discovery delta: mDNS +%d/-%d, SSDP +%d/-%d",
        len(delta["mdns"]["added"]), len(delta["mdns"]["removed"]),
        len(delta["ssdp"]["added"]), len(delta["ssdp"]["removed"]),
    )

    return delta


def _compute_reachability_delta(
    before: Dict[str, Any], after: Dict[str, Any]
) -> Dict[str, Any]:
    """Compute reachability delta between two runs.

    Args:
        before: Baseline run data.
        after: Hardened run data.

    Returns:
        Dictionary with added/removed OPEN services.
    """
    before_open = _extract_open_services(before)
    after_open = _extract_open_services(after)

    added = sorted(after_open - before_open)
    removed = sorted(before_open - after_open)

    delta = {
        "added": [{"dst_ip": ip, "port": port} for ip, port in added],
        "removed": [{"dst_ip": ip, "port": port} for ip, port in removed],
        "before_open_count": len(before_open),
        "after_open_count": len(after_open),
    }

    logger.debug(
        "Reachability delta: +%d OPEN, -%d OPEN",
        len(added), len(removed),
    )

    return delta


def _extract_open_services(run_data: Dict[str, Any]) -> Set[Tuple[str, int]]:
    """Extract set of (ip, port) tuples with OPEN state from run data.

    Args:
        run_data: Parsed run.json structure.

    Returns:
        Set of (dst_ip, port) tuples.
    """
    results = run_data.get("reachability", {}).get("results", [])
    return {
        (r["dst_ip"], r["port"])
        for r in results
        if r.get("state") == "OPEN"
    }


def _compute_score(
    run_data: Dict[str, Any],
    reachability_delta: Dict[str, Any] = None,
) -> int:
    """Compute exposure score for a run.

    Score starts at 100 and is reduced by exposures. Lower exposure = higher score.

    Args:
        run_data: Parsed run.json structure.
        reachability_delta: Optional delta for penalty on new OPEN services.

    Returns:
        Integer score (minimum 0, maximum 100).
    """
    score = SCORE_BASE

    discovery = run_data.get("discovery", {})
    mdns_count = len(discovery.get("mdns", {}).get("unique_responders", []))
    ssdp_count = len(discovery.get("ssdp", {}).get("unique_responders", []))

    score -= mdns_count * PENALTY_MDNS_RESPONDER
    score -= ssdp_count * PENALTY_SSDP_RESPONDER

    open_services = _extract_open_services(run_data)
    score -= len(open_services) * PENALTY_OPEN_PORT

    # Extra penalty for new OPEN services after hardening
    if reachability_delta:
        new_open = len(reachability_delta.get("added", []))
        score -= new_open * PENALTY_NEW_OPEN_PORT

    return max(0, min(100, score))


def _build_summary(
    discovery_delta: Dict[str, Any],
    reachability_delta: Dict[str, Any],
    before_score: int,
    after_score: int,
) -> Dict[str, str]:
    """Build human-readable summary of the diff.

    Args:
        discovery_delta: Discovery delta dictionary.
        reachability_delta: Reachability delta dictionary.
        before_score: Score of baseline run.
        after_score: Score of hardened run.

    Returns:
        Dictionary with summary text fields.
    """
    mdns_removed = len(discovery_delta["mdns"]["removed"])
    ssdp_removed = len(discovery_delta["ssdp"]["removed"])
    reach_removed = len(reachability_delta["removed"])
    reach_added = len(reachability_delta["added"])
    improvement = after_score - before_score

    if improvement > 0:
        verdict = "IMPROVED"
        description = (
            f"Network exposure improved by {improvement} points. "
            f"Removed {mdns_removed} mDNS + {ssdp_removed} SSDP responders, "
            f"{reach_removed} OPEN ports closed."
        )
    elif improvement == 0:
        verdict = "UNCHANGED"
        description = "No measurable change in network exposure."
    else:
        verdict = "DEGRADED"
        description = (
            f"Network exposure degraded by {abs(improvement)} points. "
            f"{reach_added} new OPEN ports detected."
        )

    return {
        "verdict": verdict,
        "description": description,
        "before_score": str(before_score),
        "after_score": str(after_score),
    }
