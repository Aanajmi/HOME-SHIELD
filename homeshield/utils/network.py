"""Network utility functions for HomeShield.

Cross-platform: Windows, macOS, Linux.
"""

import os
import platform
import socket
import struct
import subprocess
from typing import Optional

from homeshield.utils.logging_config import get_logger

logger = get_logger("utils.network")

IS_WINDOWS = platform.system() == "Windows"


def get_interface_ip(interface: str) -> Optional[str]:
    """Get the IPv4 address of a network interface.

    Args:
        interface: Network interface name (e.g., 'en0', 'eth0', 'wlan0')
                   or on Windows an adapter name/alias or IP address hint.

    Returns:
        IPv4 address string, or None if unavailable.
    """
    if IS_WINDOWS:
        return _get_interface_ip_windows(interface)
    return _get_interface_ip_unix(interface)


def _get_interface_ip_windows(interface: str) -> Optional[str]:
    """Resolve interface IP on Windows using multiple strategies.

    Args:
        interface: Adapter name, alias, or IP hint.

    Returns:
        IPv4 address string, or None.
    """
    # Strategy 1: If the user passed an IP address directly, validate and return it
    if validate_ip(interface):
        logger.debug("Interface arg is already an IP: %s", interface)
        return interface

    # Strategy 2: Use 'ipconfig' to find the adapter
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True, text=True, timeout=10,
        )
        current_adapter = ""
        for line in result.stdout.splitlines():
            line_stripped = line.strip()
            # Adapter header lines are not indented
            if line and not line[0].isspace() and ":" in line:
                current_adapter = line_stripped.rstrip(":").strip()
            # Look for IPv4 address under the matching adapter
            if interface.lower() in current_adapter.lower():
                if "IPv4" in line_stripped and ":" in line_stripped:
                    ip_addr = line_stripped.split(":")[-1].strip()
                    if validate_ip(ip_addr):
                        logger.debug("Interface %s has IP %s (via ipconfig)", interface, ip_addr)
                        return ip_addr
    except Exception as exc:
        logger.warning("ipconfig lookup failed for %s: %s", interface, exc)

    # Strategy 3: Use PowerShell Get-NetIPAddress
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"Get-NetIPAddress -InterfaceAlias '*{interface}*' -AddressFamily IPv4 "
             "| Select-Object -ExpandProperty IPAddress"],
            capture_output=True, text=True, timeout=10,
        )
        ip_addr = result.stdout.strip().split("\n")[0].strip()
        if ip_addr and validate_ip(ip_addr):
            logger.debug("Interface %s has IP %s (via PowerShell)", interface, ip_addr)
            return ip_addr
    except Exception as exc:
        logger.warning("PowerShell lookup failed for %s: %s", interface, exc)

    # Strategy 4: netifaces (cross-platform, if installed)
    ip = _try_netifaces(interface)
    if ip:
        return ip

    logger.error("Could not determine IP for interface %s on Windows", interface)
    return None


def _get_interface_ip_unix(interface: str) -> Optional[str]:
    """Resolve interface IP on macOS/Linux.

    Args:
        interface: Interface name (e.g., 'en0', 'eth0', 'wlan0').

    Returns:
        IPv4 address string, or None.
    """
    # Strategy 1: fcntl/ioctl (Linux)
    try:
        import fcntl
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_bytes = fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack("256s", interface[:15].encode("utf-8")),
        )
        ip_addr = socket.inet_ntoa(ip_bytes[20:24])
        sock.close()
        logger.debug("Interface %s has IP %s", interface, ip_addr)
        return ip_addr
    except (ImportError, OSError):
        logger.debug("fcntl/ioctl failed for %s, trying fallback methods", interface)

    # Strategy 2: netifaces
    ip = _try_netifaces(interface)
    if ip:
        return ip

    # Strategy 3: 'ip' command (Linux)
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip_addr = line.split()[1].split("/")[0]
                logger.debug("Interface %s has IP %s (via ip command)", interface, ip_addr)
                return ip_addr
    except Exception as exc:
        logger.warning("ip command fallback failed for %s: %s", interface, exc)

    # Strategy 4: ifconfig (macOS / older Linux)
    try:
        result = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if "inet " in line:
                parts = line.split()
                idx = parts.index("inet") + 1
                ip_addr = parts[idx]
                logger.debug("Interface %s has IP %s (via ifconfig)", interface, ip_addr)
                return ip_addr
    except Exception as exc:
        logger.warning("ifconfig fallback failed for %s: %s", interface, exc)

    logger.error("Could not determine IP for interface %s", interface)
    return None


def _try_netifaces(interface: str) -> Optional[str]:
    """Try resolving interface IP via the netifaces package.

    Args:
        interface: Interface name.

    Returns:
        IPv4 address string, or None.
    """
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_addr = addrs[netifaces.AF_INET][0]["addr"]
            logger.debug("Interface %s has IP %s (via netifaces)", interface, ip_addr)
            return ip_addr
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("netifaces lookup failed for %s: %s", interface, exc)
    return None


def get_default_ip() -> Optional[str]:
    """Get the default outbound IP address (cross-platform).

    Returns:
        IPv4 address string used for default route, or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip_addr = sock.getsockname()[0]
        sock.close()
        logger.debug("Default outbound IP: %s", ip_addr)
        return ip_addr
    except OSError as exc:
        logger.warning("Could not determine default IP: %s", exc)
        return None


def validate_ip(ip: str) -> bool:
    """Validate an IPv4 address string.

    Args:
        ip: IP address string.

    Returns:
        True if valid IPv4 address.
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
