"""Tests for HTML report generation."""

import os
import tempfile
import unittest

from homeshield.report.html_report import generate_diff_report, generate_single_run_report


class TestDiffReport(unittest.TestCase):
    """Test diff report generation."""

    def setUp(self):
        """Set up test diff data."""
        self.diff_data = {
            "before_label": "baseline_test",
            "after_label": "hardened_test",
            "timestamp_utc": "2026-03-23T00:00:00+00:00",
            "discovery_delta": {
                "mdns": {
                    "added": [],
                    "removed": ["192.168.1.10", "192.168.1.20"],
                    "before_count": 3,
                    "after_count": 1,
                },
                "ssdp": {
                    "added": [],
                    "removed": ["192.168.1.30"],
                    "before_count": 2,
                    "after_count": 1,
                },
            },
            "reachability_delta": {
                "added": [],
                "removed": [
                    {"dst_ip": "192.168.1.1", "port": 443},
                    {"dst_ip": "192.168.1.10", "port": 80},
                ],
                "before_open_count": 3,
                "after_open_count": 1,
            },
            "scores": {
                "before": 65,
                "after": 88,
                "improvement": 23,
            },
            "summary": {
                "verdict": "IMPROVED",
                "description": "Network exposure improved by 23 points.",
                "before_score": "65",
                "after_score": "88",
            },
        }

    def test_generates_html_file(self):
        """Test that HTML file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            result = generate_diff_report(self.diff_data, out_path)
            self.assertTrue(os.path.isfile(result))

    def test_html_contains_scores(self):
        """Test that HTML contains score values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            generate_diff_report(self.diff_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("65", html)
            self.assertIn("88", html)
            self.assertIn("+23", html)

    def test_html_contains_verdict(self):
        """Test that HTML contains verdict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            generate_diff_report(self.diff_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("IMPROVED", html)

    def test_html_contains_removed_ips(self):
        """Test that HTML lists removed IPs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            generate_diff_report(self.diff_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("192.168.1.10", html)
            self.assertIn("REMOVED", html)

    def test_html_is_valid_structure(self):
        """Test that HTML has proper structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            generate_diff_report(self.diff_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("<!DOCTYPE html>", html)
            self.assertIn("</html>", html)
            self.assertIn("<style>", html)

    def test_creates_parent_directory(self):
        """Test that report creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "sub", "dir", "report.html")
            result = generate_diff_report(self.diff_data, out_path)
            self.assertTrue(os.path.isfile(result))


class TestSingleRunReport(unittest.TestCase):
    """Test single-run report generation."""

    def setUp(self):
        """Set up test run data."""
        self.run_data = {
            "label": "test_run",
            "timestamp_utc": "2026-03-23T00:00:00+00:00",
            "vantage": "iot",
            "host": {"interface": "eth0", "ip": "192.168.1.100"},
            "discovery": {
                "mdns": {"unique_responders": ["192.168.1.1", "192.168.1.10"]},
                "ssdp": {"unique_responders": ["192.168.1.1"]},
            },
            "reachability": {
                "ports_tested": [80, 443],
                "results": [
                    {"dst_ip": "192.168.1.1", "port": 80, "state": "OPEN", "rtt_ms": 1.5},
                    {"dst_ip": "192.168.1.1", "port": 443, "state": "CLOSED", "rtt_ms": 0.5},
                ],
            },
        }

    def test_generates_single_run_html(self):
        """Test that single-run HTML file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "single.html")
            result = generate_single_run_report(self.run_data, out_path)
            self.assertTrue(os.path.isfile(result))

    def test_contains_run_label(self):
        """Test that HTML contains run label."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "single.html")
            generate_single_run_report(self.run_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("test_run", html)

    def test_contains_discovery_ips(self):
        """Test that HTML contains discovered IPs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "single.html")
            generate_single_run_report(self.run_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("192.168.1.1", html)
            self.assertIn("192.168.1.10", html)

    def test_contains_reachability_states(self):
        """Test that HTML contains port states."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "single.html")
            generate_single_run_report(self.run_data, out_path)
            with open(out_path) as fh:
                html = fh.read()
            self.assertIn("OPEN", html)
            self.assertIn("CLOSED", html)


if __name__ == "__main__":
    unittest.main()
