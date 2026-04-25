"""Tests for CLI argument parsing and command routing."""

import sys
import unittest
from unittest.mock import patch

from homeshield.cli import build_parser, parse_ports


class TestParsePortsFunction(unittest.TestCase):
    """Test the port parsing utility."""

    def test_valid_ports(self):
        """Test parsing valid comma-separated ports."""
        result = parse_ports("80,443,554")
        self.assertEqual(result, [80, 443, 554])

    def test_single_port(self):
        """Test parsing a single port."""
        result = parse_ports("80")
        self.assertEqual(result, [80])

    def test_ports_with_spaces(self):
        """Test parsing ports with spaces."""
        result = parse_ports("80, 443 , 554")
        self.assertEqual(result, [80, 443, 554])

    def test_invalid_port_number(self):
        """Test that invalid port raises error."""
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("80,99999")

    def test_non_numeric_port(self):
        """Test that non-numeric port raises error."""
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("80,abc")


class TestCliParser(unittest.TestCase):
    """Test CLI argument parser construction."""

    def setUp(self):
        """Set up parser."""
        self.parser = build_parser()

    def test_measure_command(self):
        """Test measure command parsing."""
        args = self.parser.parse_args([
            "measure", "--label", "test_run", "--vantage", "iot",
            "--iface", "eth0", "--rounds", "5", "--interval", "10",
            "--listen", "4", "--ports", "80,443",
        ])
        self.assertEqual(args.command, "measure")
        self.assertEqual(args.label, "test_run")
        self.assertEqual(args.vantage, "iot")
        self.assertEqual(args.iface, "eth0")
        self.assertEqual(args.rounds, 5)
        self.assertEqual(args.interval, 10.0)
        self.assertEqual(args.listen, 4.0)
        self.assertEqual(args.ports, [80, 443])

    def test_measure_defaults(self):
        """Test measure command with default values."""
        args = self.parser.parse_args(["measure", "--label", "test"])
        self.assertEqual(args.rounds, 3)
        self.assertEqual(args.interval, 10.0)
        self.assertEqual(args.listen, 4.0)
        self.assertIsNone(args.ports)
        self.assertIsNone(args.iface)

    def test_diff_command(self):
        """Test diff command parsing."""
        args = self.parser.parse_args([
            "diff", "--before", "a.json", "--after", "b.json", "--out", "diff.json",
        ])
        self.assertEqual(args.command, "diff")
        self.assertEqual(args.before, "a.json")
        self.assertEqual(args.after, "b.json")
        self.assertEqual(args.out, "diff.json")

    def test_report_with_diff(self):
        """Test report command with --diff flag."""
        args = self.parser.parse_args([
            "report", "--diff", "diff.json", "--out", "report.html",
        ])
        self.assertEqual(args.command, "report")
        self.assertEqual(args.diff, "diff.json")
        self.assertIsNone(args.run)

    def test_report_with_run(self):
        """Test report command with --run flag."""
        args = self.parser.parse_args([
            "report", "--run", "run.json",
        ])
        self.assertEqual(args.command, "report")
        self.assertEqual(args.run, "run.json")

    def test_pcap_parse_command(self):
        """Test pcap-parse command parsing."""
        args = self.parser.parse_args([
            "pcap-parse", "--pcap", "test.pcap",
        ])
        self.assertEqual(args.command, "pcap-parse")
        self.assertEqual(args.pcap, "test.pcap")

    def test_measure_requires_label(self):
        """Test that measure requires --label."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["measure"])

    def test_diff_requires_before_after(self):
        """Test that diff requires --before and --after."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["diff", "--before", "a.json"])

    def test_report_requires_diff_or_run(self):
        """Test that report requires --diff or --run."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["report", "--out", "r.html"])

    def test_version_flag(self):
        """Test --version flag."""
        with self.assertRaises(SystemExit) as cm:
            self.parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)


class TestCliIntegration(unittest.TestCase):
    """Integration tests for CLI command execution."""

    @patch("homeshield.commands.diff_cmd.execute_diff")
    def test_diff_command_execution(self, mock_diff):
        """Test that diff command calls execute_diff."""
        mock_diff.return_value = {"before_label": "a", "after_label": "b"}

        from homeshield.cli import main
        with patch("sys.argv", ["homeshield", "diff", "--before", "a.json", "--after", "b.json"]):
            try:
                main()
            except SystemExit:
                pass

    @patch("homeshield.commands.report_cmd.execute_report")
    def test_report_command_execution(self, mock_report):
        """Test that report command calls execute_report."""
        mock_report.return_value = "/tmp/report.html"

        from homeshield.cli import main
        with patch("sys.argv", ["homeshield", "report", "--diff", "diff.json"]):
            try:
                main()
            except SystemExit:
                pass


if __name__ == "__main__":
    unittest.main()
