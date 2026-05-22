"""Target validation utilities for PrivacyAware-PenAgent.

Enforces that all tool invocations only target authorized
network ranges (HackTheBox VPN, local VMs, Docker, localhost).
"""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address, ip_network

ALLOWED_TARGET_RANGES: list[str] = [
    "10.10.0.0/16",       # HackTheBox VPN range
    "10.129.0.0/16",      # HackTheBox VPN range (alternate)
    "192.168.56.0/24",    # Local VirtualBox host-only
    "172.17.0.0/16",      # Docker containers
    "127.0.0.1/32",       # Localhost
]


def validate_target(ip: str) -> bool:
    """Check whether an IP address falls within allowed ranges.

    Args:
        ip: The IPv4 address string to validate.

    Returns:
        True if the IP is within an allowed range, False otherwise.
    """
    try:
        addr: IPv4Address = ip_address(ip)  # type: ignore[assignment]
    except ValueError:
        return False

    return any(
        addr in ip_network(net, strict=False)
        for net in ALLOWED_TARGET_RANGES
    )
