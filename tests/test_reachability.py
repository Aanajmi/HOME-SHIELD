"""Tests for TCP reachability module."""

import socket
import unittest
from unittest.mock import patch, MagicMock

from homeshield.reachability.tcp_check import (
    check_single_port,
    run_reachability_checks,
    DEFAULT_PORTS,
    PORT_DESCRIPTIONS,
)


class TestCheckSinglePort(unittest.TestCase):
    """Test cases for single port checking."""

    @patch("homeshield.reachability.tcp_check.socket.socket")
    def test_open_port(self, mock_socket_class):
        """Test detection of OPEN port."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0

        result = check_single_port("192.168.1.1", 80, timeout=1.0)

        self.assertEqual(result["dst_ip"], "192.168.1.1")
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "OPEN")
        self.assertIsNotNone(result["rtt_ms"])
        mock_sock.close.assert_called_once()

    @patch("homeshield.reachability.tcp_check.socket.socket")
    def test_closed_port_linux(self, mock_socket_class):
        """Test detection of CLOSED port (Linux ECONNREFUSED=111)."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.return_value = 111

        result = check_single_port("192.168.1.1", 443, timeout=1.0)

        self.assertEqual(result["state"], "CLOSED")
        self.assertIsNotNone(result["rtt_ms"])

    @patch("homeshield.reachability.tcp_check.socket.socket")
    def test_closed_port_macos(self, mock_socket_class):
        """Test detection of CLOSED port (macOS ECONNREFUSED=61)."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.return_value = 61

        result = check_single_port("192.168.1.1", 554, timeout=1.0)

        self.assertEqual(result["state"], "CLOSED")

    @patch("homeshield.reachability.tcp_check.socket.socket")
    def test_timeout_port(self, mock_socket_class):
        """Test detection of TIMEOUT port."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect_ex.side_effect = socket.timeout("timed out")

        result = check_single_port("192.168.1.1", 445, timeout=0.5)

        self.assertEqual(result["state"], "TIMEOUT")
        self.assertIsNone(result["rtt_ms"])

    @patch("homeshield.reachability.tcp_check.socket.socket")
    def test_os_error_refused(self, mock_socket_class):
        """Test OSError with connection refused errno."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        error = OSError()
        error.errno = 111
        mock_sock.connect_ex.side_effect = error

        result = check_single_port("192.168.1.1", 80, timeout=1.0)

        self.assertEqual(result["state"], "CLOSED")

    def test_result_structure(self):
        """Test that result has all required fields."""
        with patch("homeshield.reachability.tcp_check.socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0

            result = check_single_port("10.0.0.1", 80)

            self.assertIn("dst_ip", result)
            self.assertIn("port", result)
            self.assertIn("state", result)
            self.assertIn("rtt_ms", result)
            self.assertIn("service", result)

    def test_service_description(self):
        """Test that known ports get correct service names."""
        with patch("homeshield.reachability.tcp_check.socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0

            result = check_single_port("10.0.0.1", 443)
            self.assertEqual(result["service"], "HTTPS")

            result = check_single_port("10.0.0.1", 1883)
            self.assertEqual(result["service"], "MQTT")


class TestRunReachabilityChecks(unittest.TestCase):
    """Test cases for batch reachability checks."""

    @patch("homeshield.reachability.tcp_check.check_single_port")
    def test_empty_ips(self, mock_check):
        """Test handling of empty IP list."""
        result = run_reachability_checks([], ports=[80])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["ports_tested"], [80])
        mock_check.assert_not_called()

    @patch("homeshield.reachability.tcp_check.check_single_port")
    def test_results_sorted(self, mock_check):
        """Test that results are sorted by IP then port."""
        mock_check.side_effect = lambda ip, port, timeout: {
            "dst_ip": ip, "port": port, "state": "OPEN", "rtt_ms": 1.0, "service": "HTTP",
        }

        result = run_reachability_checks(
            ["192.168.1.2", "192.168.1.1"],
            ports=[443, 80],
            workers=2,
        )

        ips_ports = [(r["dst_ip"], r["port"]) for r in result["results"]]
        self.assertEqual(ips_ports, sorted(ips_ports))

    @patch("homeshield.reachability.tcp_check.check_single_port")
    def test_correct_number_of_checks(self, mock_check):
        """Test that all IP:port combinations are checked."""
        mock_check.return_value = {
            "dst_ip": "10.0.0.1", "port": 80, "state": "CLOSED", "rtt_ms": 0.5, "service": "HTTP",
        }

        result = run_reachability_checks(
            ["10.0.0.1", "10.0.0.2"],
            ports=[80, 443],
            workers=2,
        )

        self.assertEqual(len(result["results"]), 4)  # 2 IPs x 2 ports

    def test_default_ports(self):
        """Test that DEFAULT_PORTS contains expected ports."""
        self.assertIn(80, DEFAULT_PORTS)
        self.assertIn(443, DEFAULT_PORTS)
        self.assertIn(554, DEFAULT_PORTS)
        self.assertIn(445, DEFAULT_PORTS)
        self.assertIn(1883, DEFAULT_PORTS)

    def test_ports_tested_sorted(self):
        """Test that ports_tested in output is sorted."""
        with patch("homeshield.reachability.tcp_check.check_single_port") as mock:
            mock.return_value = {
                "dst_ip": "10.0.0.1", "port": 80, "state": "OPEN", "rtt_ms": 1.0, "service": "HTTP",
            }
            result = run_reachability_checks(["10.0.0.1"], ports=[443, 80, 8080])
            self.assertEqual(result["ports_tested"], [80, 443, 8080])


if __name__ == "__main__":
    unittest.main()
