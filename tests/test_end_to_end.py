"""End-to-end integration tests for HomeShield.

Tests the full workflow: measure (mocked) -> diff -> report pipeline.
"""

import csv
import json
import os
import tempfile
import unittest

from homeshield.commands.diff_cmd import execute_diff
from homeshield.commands.report_cmd import execute_report
from homeshield.utils.output import write_json


class TestEndToEndPipeline(unittest.TestCase):
    """Test full measure -> diff -> report pipeline."""

    def setUp(self):
        """Create temporary directory with sample run data."""
        self.tmpdir = tempfile.mkdtemp()

        # Create baseline run data
        self.baseline_dir = os.path.join(self.tmpdir, "outputs", "baseline_iot")
        os.makedirs(self.baseline_dir)

        self.baseline_data = {
            "label": "baseline_iot",
            "timestamp_utc": "2026-03-23T10:00:00+00:00",
            "vantage": "iot",
            "host": {"interface": "eth0", "ip": "192.168.1.100"},
            "schedule": {"rounds": 3, "interval": 10.0, "listen": 4.0},
            "discovery": {
                "mdns": {
                    "unique_responders": [
                        "192.168.1.1", "192.168.1.10",
                        "192.168.1.20", "192.168.1.30",
                    ],
                    "per_round": {
                        "1": ["192.168.1.1", "192.168.1.10"],
                        "2": ["192.168.1.1", "192.168.1.20"],
                        "3": ["192.168.1.1", "192.168.1.10", "192.168.1.30"],
                    },
                },
                "ssdp": {
                    "unique_responders": ["192.168.1.1", "192.168.1.40"],
                    "per_round": {
                        "1": ["192.168.1.1"],
                        "2": ["192.168.1.40"],
                    },
                    "headers": {
                        "192.168.1.1": {"SERVER": "Linux UPnP", "USN": "uuid:1", "ST": "", "LOCATION": ""},
                    },
                },
            },
            "reachability": {
                "ports_tested": [80, 443, 554, 445],
                "results": [
                    {"dst_ip": "192.168.1.1", "port": 80, "state": "OPEN", "rtt_ms": 1.2, "service": "HTTP"},
                    {"dst_ip": "192.168.1.1", "port": 443, "state": "OPEN", "rtt_ms": 2.1, "service": "HTTPS"},
                    {"dst_ip": "192.168.1.1", "port": 554, "state": "CLOSED", "rtt_ms": 0.3, "service": "RTSP"},
                    {"dst_ip": "192.168.1.1", "port": 445, "state": "TIMEOUT", "rtt_ms": None, "service": "SMB"},
                    {"dst_ip": "192.168.1.10", "port": 80, "state": "OPEN", "rtt_ms": 5.0, "service": "HTTP"},
                    {"dst_ip": "192.168.1.10", "port": 443, "state": "TIMEOUT", "rtt_ms": None, "service": "HTTPS"},
                    {"dst_ip": "192.168.1.20", "port": 80, "state": "CLOSED", "rtt_ms": 0.8, "service": "HTTP"},
                    {"dst_ip": "192.168.1.30", "port": 554, "state": "OPEN", "rtt_ms": 12.0, "service": "RTSP"},
                ],
            },
            "artifacts": {
                "run_json": os.path.join(self.baseline_dir, "run.json"),
                "discovery_csv": os.path.join(self.baseline_dir, "discovery.csv"),
                "reachability_csv": os.path.join(self.baseline_dir, "reachability.csv"),
            },
        }
        write_json(self.baseline_data, os.path.join(self.baseline_dir, "run.json"))

        # Create hardened run data
        self.hardened_dir = os.path.join(self.tmpdir, "outputs", "hardened_iot")
        os.makedirs(self.hardened_dir)

        self.hardened_data = {
            "label": "hardened_iot",
            "timestamp_utc": "2026-03-23T12:00:00+00:00",
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
                    "unique_responders": [],
                    "per_round": {},
                    "headers": {},
                },
            },
            "reachability": {
                "ports_tested": [80, 443, 554, 445],
                "results": [
                    {"dst_ip": "192.168.1.1", "port": 80, "state": "OPEN", "rtt_ms": 1.0, "service": "HTTP"},
                    {"dst_ip": "192.168.1.1", "port": 443, "state": "CLOSED", "rtt_ms": 0.4, "service": "HTTPS"},
                    {"dst_ip": "192.168.1.1", "port": 554, "state": "CLOSED", "rtt_ms": 0.3, "service": "RTSP"},
                    {"dst_ip": "192.168.1.1", "port": 445, "state": "TIMEOUT", "rtt_ms": None, "service": "SMB"},
                ],
            },
            "artifacts": {
                "run_json": os.path.join(self.hardened_dir, "run.json"),
                "discovery_csv": os.path.join(self.hardened_dir, "discovery.csv"),
                "reachability_csv": os.path.join(self.hardened_dir, "reachability.csv"),
            },
        }
        write_json(self.hardened_data, os.path.join(self.hardened_dir, "run.json"))

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_diff_pipeline(self):
        """Test diff produces valid output from two runs."""
        diff_path = os.path.join(self.tmpdir, "outputs", "diff.json")

        diff_data = execute_diff(
            before_path=os.path.join(self.baseline_dir, "run.json"),
            after_path=os.path.join(self.hardened_dir, "run.json"),
            output_path=diff_path,
        )

        # Verify file was written
        self.assertTrue(os.path.isfile(diff_path))

        # Verify structure
        self.assertIn("before_label", diff_data)
        self.assertIn("after_label", diff_data)
        self.assertIn("discovery_delta", diff_data)
        self.assertIn("reachability_delta", diff_data)
        self.assertIn("scores", diff_data)
        self.assertIn("summary", diff_data)

        # Verify correctness
        self.assertEqual(diff_data["before_label"], "baseline_iot")
        self.assertEqual(diff_data["after_label"], "hardened_iot")

        # mDNS should show 3 removed (10, 20, 30)
        mdns_removed = diff_data["discovery_delta"]["mdns"]["removed"]
        self.assertEqual(len(mdns_removed), 3)
        self.assertIn("192.168.1.10", mdns_removed)

        # Score should improve
        self.assertGreater(diff_data["scores"]["after"], diff_data["scores"]["before"])

    def test_full_report_from_diff(self):
        """Test HTML report generation from diff."""
        diff_path = os.path.join(self.tmpdir, "diff.json")
        report_path = os.path.join(self.tmpdir, "reports", "before_after.html")

        # Generate diff first
        execute_diff(
            before_path=os.path.join(self.baseline_dir, "run.json"),
            after_path=os.path.join(self.hardened_dir, "run.json"),
            output_path=diff_path,
        )

        # Generate report from diff
        result = execute_report(
            diff_path=diff_path,
            output_path=report_path,
        )

        self.assertTrue(os.path.isfile(result))

        with open(result) as fh:
            html = fh.read()

        self.assertIn("HomeShield", html)
        self.assertIn("IMPROVED", html)
        self.assertIn("192.168.1.10", html)

    def test_full_report_from_single_run(self):
        """Test HTML report from single run.json."""
        report_path = os.path.join(self.tmpdir, "reports", "baseline.html")

        result = execute_report(
            run_path=os.path.join(self.baseline_dir, "run.json"),
            output_path=report_path,
        )

        self.assertTrue(os.path.isfile(result))

        with open(result) as fh:
            html = fh.read()

        self.assertIn("baseline_iot", html)
        self.assertIn("OPEN", html)

    def test_diff_json_is_loadable(self):
        """Test that diff.json can be loaded and re-parsed."""
        from homeshield.utils.output import load_json

        diff_path = os.path.join(self.tmpdir, "diff.json")
        execute_diff(
            before_path=os.path.join(self.baseline_dir, "run.json"),
            after_path=os.path.join(self.hardened_dir, "run.json"),
            output_path=diff_path,
        )

        loaded = load_json(diff_path)
        self.assertIsInstance(loaded, dict)
        self.assertIn("scores", loaded)

    def test_score_reflects_exposure_reduction(self):
        """Test that significant exposure reduction shows in scores."""
        diff_path = os.path.join(self.tmpdir, "diff.json")
        diff_data = execute_diff(
            before_path=os.path.join(self.baseline_dir, "run.json"),
            after_path=os.path.join(self.hardened_dir, "run.json"),
            output_path=diff_path,
        )

        # Baseline has 4 mDNS + 2 SSDP + 4 OPEN ports = lots of exposure
        # Hardened has 1 mDNS + 0 SSDP + 1 OPEN port = much less
        improvement = diff_data["scores"]["improvement"]
        self.assertGreater(improvement, 10)  # Significant improvement


if __name__ == "__main__":
    unittest.main()
