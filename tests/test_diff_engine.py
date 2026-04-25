"""Tests for the diff and scoring engine."""

import json
import os
import tempfile
import unittest

from homeshield.diff.engine import (
    compute_diff,
    _compute_score,
    _extract_open_services,
    SCORE_BASE,
    PENALTY_MDNS_RESPONDER,
    PENALTY_OPEN_PORT,
)


class TestDiffEngine(unittest.TestCase):
    """Test cases for diff computation."""

    def setUp(self):
        """Set up test data."""
        self.before_run = {
            "label": "baseline_test",
            "timestamp_utc": "2026-03-23T00:00:00+00:00",
            "vantage": "iot",
            "host": {"interface": "eth0", "ip": "192.168.1.100"},
            "schedule": {"rounds": 3, "interval": 10.0, "listen": 4.0},
            "discovery": {
                "mdns": {
                    "unique_responders": ["192.168.1.1", "192.168.1.10", "192.168.1.20"],
                    "per_round": {
                        "1": ["192.168.1.1", "192.168.1.10"],
                        "2": ["192.168.1.1", "192.168.1.20"],
                        "3": ["192.168.1.1", "192.168.1.10", "192.168.1.20"],
                    },
                },
                "ssdp": {
                    "unique_responders": ["192.168.1.1", "192.168.1.30"],
                    "per_round": {"1": ["192.168.1.1"], "2": ["192.168.1.30"]},
                    "headers": {},
                },
            },
            "reachability": {
                "ports_tested": [80, 443, 554],
                "results": [
                    {"dst_ip": "192.168.1.1", "port": 80, "state": "OPEN", "rtt_ms": 1.5},
                    {"dst_ip": "192.168.1.1", "port": 443, "state": "OPEN", "rtt_ms": 2.0},
                    {"dst_ip": "192.168.1.1", "port": 554, "state": "CLOSED", "rtt_ms": 0.5},
                    {"dst_ip": "192.168.1.10", "port": 80, "state": "OPEN", "rtt_ms": 3.0},
                    {"dst_ip": "192.168.1.10", "port": 443, "state": "TIMEOUT", "rtt_ms": None},
                    {"dst_ip": "192.168.1.20", "port": 80, "state": "TIMEOUT", "rtt_ms": None},
                ],
            },
        }

        self.after_run = {
            "label": "hardened_test",
            "timestamp_utc": "2026-03-23T01:00:00+00:00",
            "vantage": "iot",
            "host": {"interface": "eth0", "ip": "192.168.1.100"},
            "schedule": {"rounds": 3, "interval": 10.0, "listen": 4.0},
            "discovery": {
                "mdns": {
                    "unique_responders": ["192.168.1.1"],
                    "per_round": {
                        "1": ["192.168.1.1"],
                        "2": ["192.168.1.1"],
                        "3": ["192.168.1.1"],
                    },
                },
                "ssdp": {
                    "unique_responders": ["192.168.1.1"],
                    "per_round": {"1": ["192.168.1.1"]},
                    "headers": {},
                },
            },
            "reachability": {
                "ports_tested": [80, 443, 554],
                "results": [
                    {"dst_ip": "192.168.1.1", "port": 80, "state": "OPEN", "rtt_ms": 1.2},
                    {"dst_ip": "192.168.1.1", "port": 443, "state": "CLOSED", "rtt_ms": 0.5},
                    {"dst_ip": "192.168.1.1", "port": 554, "state": "CLOSED", "rtt_ms": 0.3},
                ],
            },
        }

    def test_compute_diff_labels(self):
        """Test that diff includes correct labels."""
        diff = compute_diff(self.before_run, self.after_run)
        self.assertEqual(diff["before_label"], "baseline_test")
        self.assertEqual(diff["after_label"], "hardened_test")

    def test_discovery_delta_mdns(self):
        """Test mDNS delta computation — removed IPs detected."""
        diff = compute_diff(self.before_run, self.after_run)
        mdns = diff["discovery_delta"]["mdns"]
        self.assertEqual(mdns["removed"], ["192.168.1.10", "192.168.1.20"])
        self.assertEqual(mdns["added"], [])
        self.assertEqual(mdns["before_count"], 3)
        self.assertEqual(mdns["after_count"], 1)

    def test_discovery_delta_ssdp(self):
        """Test SSDP delta computation."""
        diff = compute_diff(self.before_run, self.after_run)
        ssdp = diff["discovery_delta"]["ssdp"]
        self.assertEqual(ssdp["removed"], ["192.168.1.30"])
        self.assertEqual(ssdp["added"], [])

    def test_reachability_delta(self):
        """Test reachability delta — OPEN ports removed after hardening."""
        diff = compute_diff(self.before_run, self.after_run)
        reach = diff["reachability_delta"]
        removed = [(r["dst_ip"], r["port"]) for r in reach["removed"]]
        self.assertIn(("192.168.1.1", 443), removed)
        self.assertIn(("192.168.1.10", 80), removed)
        self.assertEqual(reach["before_open_count"], 3)
        self.assertEqual(reach["after_open_count"], 1)

    def test_score_improvement(self):
        """Test that hardened run has higher score than baseline."""
        diff = compute_diff(self.before_run, self.after_run)
        scores = diff["scores"]
        self.assertGreater(scores["after"], scores["before"])
        self.assertGreater(scores["improvement"], 0)

    def test_score_computation_base(self):
        """Test score starts at 100 with no exposures."""
        empty_run = {
            "discovery": {"mdns": {"unique_responders": []}, "ssdp": {"unique_responders": []}},
            "reachability": {"results": []},
        }
        score = _compute_score(empty_run)
        self.assertEqual(score, SCORE_BASE)

    def test_score_deduction_mdns(self):
        """Test score deduction for mDNS responders."""
        run = {
            "discovery": {
                "mdns": {"unique_responders": ["10.0.0.1", "10.0.0.2"]},
                "ssdp": {"unique_responders": []},
            },
            "reachability": {"results": []},
        }
        score = _compute_score(run)
        expected = SCORE_BASE - (2 * PENALTY_MDNS_RESPONDER)
        self.assertEqual(score, expected)

    def test_score_minimum_zero(self):
        """Test that score does not go below 0."""
        run = {
            "discovery": {
                "mdns": {"unique_responders": [f"10.0.0.{i}" for i in range(50)]},
                "ssdp": {"unique_responders": [f"10.0.1.{i}" for i in range(50)]},
            },
            "reachability": {
                "results": [
                    {"dst_ip": f"10.0.0.{i}", "port": 80, "state": "OPEN"}
                    for i in range(50)
                ],
            },
        }
        score = _compute_score(run)
        self.assertEqual(score, 0)

    def test_extract_open_services(self):
        """Test extraction of OPEN service tuples."""
        services = _extract_open_services(self.before_run)
        self.assertIn(("192.168.1.1", 80), services)
        self.assertIn(("192.168.1.1", 443), services)
        self.assertIn(("192.168.1.10", 80), services)
        self.assertNotIn(("192.168.1.1", 554), services)  # CLOSED
        self.assertEqual(len(services), 3)

    def test_summary_verdict_improved(self):
        """Test summary verdict for improved run."""
        diff = compute_diff(self.before_run, self.after_run)
        self.assertEqual(diff["summary"]["verdict"], "IMPROVED")

    def test_summary_verdict_unchanged(self):
        """Test summary verdict when runs are identical."""
        diff = compute_diff(self.before_run, self.before_run)
        self.assertEqual(diff["summary"]["verdict"], "UNCHANGED")

    def test_diff_deterministic_ordering(self):
        """Test that diff output has deterministic ordering."""
        diff1 = compute_diff(self.before_run, self.after_run)
        diff2 = compute_diff(self.before_run, self.after_run)
        self.assertEqual(
            diff1["discovery_delta"]["mdns"]["removed"],
            diff2["discovery_delta"]["mdns"]["removed"],
        )

    def test_empty_discovery(self):
        """Test diff handles empty discovery gracefully."""
        empty = {
            "label": "empty",
            "discovery": {"mdns": {"unique_responders": []}, "ssdp": {"unique_responders": []}},
            "reachability": {"results": []},
        }
        diff = compute_diff(empty, empty)
        self.assertEqual(diff["discovery_delta"]["mdns"]["added"], [])
        self.assertEqual(diff["discovery_delta"]["mdns"]["removed"], [])


class TestDiffWithFiles(unittest.TestCase):
    """Test diff with actual file I/O."""

    def test_write_and_load_diff(self):
        """Test writing diff.json and loading it back."""
        from homeshield.utils.output import write_json, load_json

        before_run = {
            "label": "before",
            "discovery": {
                "mdns": {"unique_responders": ["10.0.0.1"]},
                "ssdp": {"unique_responders": []},
            },
            "reachability": {"results": []},
        }
        after_run = {
            "label": "after",
            "discovery": {
                "mdns": {"unique_responders": []},
                "ssdp": {"unique_responders": []},
            },
            "reachability": {"results": []},
        }

        diff = compute_diff(before_run, after_run)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmppath = f.name

        try:
            write_json(diff, tmppath)
            loaded = load_json(tmppath)
            self.assertEqual(loaded["before_label"], "before")
            self.assertEqual(loaded["after_label"], "after")
            self.assertEqual(loaded["discovery_delta"]["mdns"]["removed"], ["10.0.0.1"])
        finally:
            os.unlink(tmppath)


if __name__ == "__main__":
    unittest.main()
