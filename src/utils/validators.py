"""src/utils/validators.py — Target IP/hostname validation.

SECURITY CRITICAL: Every tool wrapper that accepts a target IP MUST call
``validate_target()`` before executing any network operation.

Owner: Vighnesh (Member B) — shared security foundation.
"""

from __future__ import annotations

import ipaddress
import socket

from src.config.settings import ALLOWED_TARGET_RANGES
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


class TargetValidationError(ValueError):
    """Raised when a target IP is outside the allowed scan ranges."""


def validate_target(target: str) -> bool:
    """Validate that a target IP/hostname is within allowed pentest ranges.

    Resolves hostnames to IPs before range check so that DNS-based targets
    (e.g. HackTheBox machine FQDNs) are also validated correctly.

    Args:
        target: IPv4 address string or hostname to validate.

    Returns:
        ``True`` if the target is in an allowed range.

    Raises:
        TargetValidationError: If the target is outside any allowed range or
            cannot be resolved.

    Example::

        validate_target("10.10.11.230")  # OK for HTB
        validate_target("8.8.8.8")        # raises TargetValidationError
    """
    try:
        ip = _resolve_to_ip(target)
    except OSError as exc:
        logger.error(
            "Target resolution failed — blocking scan",
            extra={"target": target, "error": str(exc)},
        )
        raise TargetValidationError(
            f"Cannot resolve target '{target}': {exc}"
        ) from exc

    ip_obj = ipaddress.ip_address(ip)

    for allowed_range in ALLOWED_TARGET_RANGES:
        if ip_obj in ipaddress.ip_network(allowed_range, strict=False):
            logger.debug(
                "Target validated",
                extra={"target": target, "resolved_ip": ip, "matched_range": allowed_range},
            )
            return True

    logger.critical(
        "Security boundary violation — target not in allowed ranges",
        extra={
            "action": "scan_blocked",
            "target": target,
            "resolved_ip": ip,
            "blocked_reason": "IP not in ALLOWED_TARGET_RANGES",
        },
    )
    raise TargetValidationError(
        f"Target '{target}' ({ip}) is not in any allowed pentest range. "
        f"Allowed: {ALLOWED_TARGET_RANGES}"
    )


def _resolve_to_ip(target: str) -> str:
    """Resolve a target to an IPv4 address string.

    Args:
        target: IP address string or resolvable hostname.

    Returns:
        Resolved IPv4 address as a string.

    Raises:
        OSError: If the hostname cannot be resolved.
    """
    try:
        # If it's already a valid IP, just return it.
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Resolve hostname.
    return socket.gethostbyname(target)


def is_valid_port(port: int) -> bool:
    """Check whether a port number is in the valid TCP/UDP range.

    Args:
        port: Integer port number to validate.

    Returns:
        ``True`` if the port is between 1 and 65535 inclusive.
    """
    return 1 <= port <= 65535


def sanitise_module_path(module_path: str) -> str:
    """Normalise a Metasploit module path and reject obviously invalid ones.

    Args:
        module_path: Raw module path string from LLM output.

    Returns:
        Sanitised module path string.

    Raises:
        ValueError: If the module path contains forbidden characters.
    """
    forbidden = [";", "&", "|", "$", "`", "\n", "\r"]
    for char in forbidden:
        if char in module_path:
            raise ValueError(
                f"Module path contains forbidden character '{char}': {module_path!r}"
            )
    # Normalise slashes.
    return module_path.strip().replace("\\", "/")

