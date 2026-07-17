"""Unit tests for the Sensitivity Classifier.

This test suite verifies regex pattern matching and scoring rules for
detecting sensitive data.
"""

from __future__ import annotations

import pytest
from src.router.sensitivity import classify_sensitivity


def test_empty_or_none_text() -> None:
    """Test that empty or None input returns 0.0 score."""
    assert classify_sensitivity("") == 0.0


def test_clean_text() -> None:
    """Test that normal text without sensitive keywords returns 0.0."""
    text = "Hello world! This is a simple test prompt for scanning tasks."
    assert classify_sensitivity(text) == 0.0


def test_ip_address_detection() -> None:
    """Test that IPv4 addresses match and score appropriately."""
    text_ip = "Scanning target 10.10.10.1 using nmap."
    score = classify_sensitivity(text_ip)
    assert score >= 0.4


def test_credential_detection() -> None:
    """Test that credential patterns are matched and scored high."""
    text_pass = "Logging in with user=admin password=MySecret123!"
    assert classify_sensitivity(text_pass) >= 0.9

    text_key = "Setting key = api_key:sk-123456789"
    assert classify_sensitivity(text_key) >= 0.9


def test_session_keyword_detection() -> None:
    """Test that session related keywords trigger mild sensitivity."""
    text = "Extracting session_id from response headers."
    assert classify_sensitivity(text) >= 0.3


def test_file_paths() -> None:
    """Test that directory paths add sensitivity."""
    win_text = "Checking file in C:\\Windows\\System32\\cmd.exe"
    assert classify_sensitivity(win_text) >= 0.3

    unix_text = "Reading log file in /var/log/syslog"
    assert classify_sensitivity(unix_text) >= 0.3


def test_critical_rules() -> None:
    """Test rules that should immediately trigger maximum sensitivity (1.0)."""
    ssh_key_text = "-----BEGIN OPENSSH PRIVATE KEY-----\nssh-ed25519 AAAAC3...\n"
    assert classify_sensitivity(ssh_key_text) == 1.0

    linux_config_text = "The config file is located at /etc/passwd on the target."
    assert classify_sensitivity(linux_config_text) == 1.0


def test_cumulative_scoring() -> None:
    """Test that multiple non-critical matches accumulate score, capped at 1.0."""
    # IPv4 (0.4) + Unix Path (0.3) = 0.7
    text = "Target 192.168.1.1 has files in /usr/bin/local"
    assert classify_sensitivity(text) == pytest.approx(0.7)

    # IPv4 (0.4) + Unix Path (0.3) + Session ID (0.3) = 1.0
    text_max = "Target 192.168.1.1 session_id at /usr/bin/local"
    assert classify_sensitivity(text_max) == 1.0
