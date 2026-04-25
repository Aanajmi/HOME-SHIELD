"""Tests for discovery modules (mDNS and SSDP)."""

import struct
import unittest
from unittest.mock import patch, MagicMock

from homeshield.discovery.mdns import (
    _build_mdns_query,
    _is_mdns_response,
    MDNS_MULTICAST_ADDR,
    MDNS_PORT,
)
from homeshield.discovery.ssdp import (
    _parse_ssdp_headers,
    SSDP_MULTICAST_ADDR,
    SSDP_PORT,
    SSDP_MSEARCH,
)


class TestMdnsQueryBuilder(unittest.TestCase):
    """Test mDNS query packet construction."""

    def test_query_packet_length(self):
        """Test that query packet has reasonable length."""
        packet = _build_mdns_query()
        self.assertGreater(len(packet), 12)  # At least DNS header

    def test_query_has_dns_header(self):
        """Test that packet starts with valid DNS header."""
        packet = _build_mdns_query()
        # Unpack first 12 bytes as DNS header
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", packet[:12]
        )
        self.assertEqual(tx_id, 0)    # ID should be 0 for mDNS
        self.assertEqual(flags, 0)    # Standard query
        self.assertEqual(qdcount, 1)  # One question
        self.assertEqual(ancount, 0)
        self.assertEqual(nscount, 0)
        self.assertEqual(arcount, 0)

    def test_query_contains_service_name(self):
        """Test that query packet contains the PTR query labels."""
        packet = _build_mdns_query()
        # Check for encoded labels
        self.assertIn(b"_services", packet)
        self.assertIn(b"_dns-sd", packet)
        self.assertIn(b"_udp", packet)
        self.assertIn(b"local", packet)

    def test_query_ends_with_ptr_type(self):
        """Test that query ends with PTR type (12) and IN class (1)."""
        packet = _build_mdns_query()
        # Last 4 bytes should be QTYPE=12, QCLASS=1
        qtype, qclass = struct.unpack("!HH", packet[-4:])
        self.assertEqual(qtype, 12)   # PTR
        self.assertEqual(qclass, 1)   # IN


class TestMdnsResponseDetection(unittest.TestCase):
    """Test mDNS response identification."""

    def test_response_detected(self):
        """Test that DNS response (QR=1) is detected."""
        # Build a fake DNS response header with QR bit set
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        self.assertTrue(_is_mdns_response(header))

    def test_query_not_detected_as_response(self):
        """Test that DNS query (QR=0) is not detected as response."""
        header = struct.pack("!HHHHHH", 0, 0x0000, 1, 0, 0, 0)
        self.assertFalse(_is_mdns_response(header))

    def test_short_packet_rejected(self):
        """Test that too-short packet is rejected."""
        self.assertFalse(_is_mdns_response(b"\x00\x00"))
        self.assertFalse(_is_mdns_response(b""))


class TestMdnsConstants(unittest.TestCase):
    """Test mDNS protocol constants."""

    def test_multicast_address(self):
        """Test mDNS multicast address."""
        self.assertEqual(MDNS_MULTICAST_ADDR, "224.0.0.251")

    def test_port(self):
        """Test mDNS port."""
        self.assertEqual(MDNS_PORT, 5353)


class TestSsdpHeaderParsing(unittest.TestCase):
    """Test SSDP response header parsing."""

    def test_parse_valid_headers(self):
        """Test parsing valid SSDP response headers."""
        response = (
            "HTTP/1.1 200 OK\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            "ST: upnp:rootdevice\r\n"
            "USN: uuid:12345::upnp:rootdevice\r\n"
            "SERVER: Linux/4.15 UPnP/1.0 MiniUPnPd/2.1\r\n"
            "LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n"
            "\r\n"
        ).encode("utf-8")

        headers = _parse_ssdp_headers(response)
        self.assertEqual(headers["ST"], "upnp:rootdevice")
        self.assertIn("uuid:12345", headers["USN"])
        self.assertIn("Linux", headers["SERVER"])
        self.assertIn("192.168.1.1", headers["LOCATION"])

    def test_parse_empty_data(self):
        """Test parsing empty data returns empty dict."""
        headers = _parse_ssdp_headers(b"")
        self.assertEqual(headers, {})

    def test_parse_malformed_data(self):
        """Test parsing malformed data doesn't crash."""
        headers = _parse_ssdp_headers(b"\xff\xfe\xfd")
        self.assertIsInstance(headers, dict)


class TestSsdpConstants(unittest.TestCase):
    """Test SSDP protocol constants."""

    def test_multicast_address(self):
        """Test SSDP multicast address."""
        self.assertEqual(SSDP_MULTICAST_ADDR, "239.255.255.250")

    def test_port(self):
        """Test SSDP port."""
        self.assertEqual(SSDP_PORT, 1900)

    def test_msearch_format(self):
        """Test M-SEARCH request format."""
        self.assertIn("M-SEARCH", SSDP_MSEARCH)
        self.assertIn("ssdp:all", SSDP_MSEARCH)
        self.assertIn("MX: 2", SSDP_MSEARCH)
        self.assertIn('ssdp:discover', SSDP_MSEARCH)


if __name__ == "__main__":
    unittest.main()
