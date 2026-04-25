"""Tests for PCAP parser module."""

import unittest
from unittest.mock import patch

from homeshield.pcap.parser import (
    is_tshark_available,
    _parse_tshark_output,
)


class TestTsharkAvailability(unittest.TestCase):
    """Test tshark availability checks."""

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_tshark_available(self, mock_which):
        """Test tshark detected when present."""
        self.assertTrue(is_tshark_available())

    @patch("shutil.which", return_value=None)
    def test_tshark_not_available(self, mock_which):
        """Test tshark not detected when absent."""
        self.assertFalse(is_tshark_available())


class TestTsharkOutputParsing(unittest.TestCase):
    """Test tshark output parsing."""

    def test_parse_mdns_output(self):
        """Test parsing typical mDNS tshark output."""
        output = (
            "ip_src|dns_qry_name|dns_resp_name\n"
            "192.168.1.1|_services._dns-sd._udp.local|_http._tcp.local\n"
            "192.168.1.10||mydevice.local\n"
        )
        entries = _parse_tshark_output(output, "mdns")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["ip_src"], "192.168.1.1")
        self.assertEqual(entries[1]["ip_src"], "192.168.1.10")

    def test_parse_ssdp_output(self):
        """Test parsing typical SSDP tshark output."""
        output = (
            "ip_src|http_server|http_location\n"
            "192.168.1.1|Linux/4.15 UPnP/1.0|http://192.168.1.1:5000/desc.xml\n"
        )
        entries = _parse_tshark_output(output, "ssdp")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip_src"], "192.168.1.1")

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        entries = _parse_tshark_output("", "mdns")
        self.assertEqual(entries, [])

    def test_parse_header_only(self):
        """Test parsing output with header but no data."""
        output = "ip_src|dns_qry_name\n"
        entries = _parse_tshark_output(output, "mdns")
        self.assertEqual(entries, [])

    def test_parse_mismatched_columns(self):
        """Test that rows with wrong column count are skipped."""
        output = (
            "ip_src|dns_qry_name|dns_resp_name\n"
            "192.168.1.1|test\n"  # only 2 columns instead of 3
            "192.168.1.2|test|test2\n"
        )
        entries = _parse_tshark_output(output, "mdns")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip_src"], "192.168.1.2")


if __name__ == "__main__":
    unittest.main()
