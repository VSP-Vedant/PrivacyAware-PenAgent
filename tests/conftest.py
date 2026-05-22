"""Shared pytest fixtures for PrivacyAware-PenAgent tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_nmap_xml(fixtures_dir: Path) -> str:
    """Return contents of sample Nmap XML output."""
    xml_path = fixtures_dir / "nmap_sample.xml"
    return xml_path.read_text(encoding="utf-8")


@pytest.fixture
def sample_htb_target() -> str:
    """Return a valid HackTheBox target IP."""
    return "10.10.10.5"


@pytest.fixture
def sample_blocked_target() -> str:
    """Return a target IP outside allowed ranges."""
    return "8.8.8.8"


@pytest.fixture
def sample_localhost() -> str:
    """Return localhost IP."""
    return "127.0.0.1"
