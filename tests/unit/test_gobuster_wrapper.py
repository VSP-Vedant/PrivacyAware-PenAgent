"""Unit tests for Gobuster wrapper module."""

from __future__ import annotations

import pytest

from src.tools.gobuster_wrapper import (
    GobusterResult,
    GobusterWrapper,
    WebEndpoint,
)


SAMPLE_GOBUSTER_OUTPUT = """\
/index.html           (Status: 200) [Size: 10918]
/images               (Status: 301) [Size: 313] [--> http://10.10.10.5/images/]
/login                (Status: 200) [Size: 1525]
/admin                (Status: 403) [Size: 277]
/config.php           (Status: 302) [Size: 0] [--> /login]
/missing              (Status: 404) [Size: 196]
/secret               (Status: 200) [Size: 3102]
/notfound             (Status: 404) [Size: 196]
"""


class TestWebEndpoint:
    """Tests for WebEndpoint dataclass."""

    def test_web_endpoint_creation(self) -> None:
        """Test basic WebEndpoint instantiation."""
        endpoint = WebEndpoint(
            url="http://10.10.10.5/admin",
            status_code=403,
            content_length=277,
        )
        assert endpoint.url == "http://10.10.10.5/admin"
        assert endpoint.status_code == 403
        assert endpoint.content_length == 277

    def test_web_endpoint_with_redirect(self) -> None:
        """Test WebEndpoint with redirect URL."""
        endpoint = WebEndpoint(
            url="http://10.10.10.5/config.php",
            status_code=302,
            content_length=0,
            redirect_url="/login",
        )
        assert endpoint.redirect_url == "/login"

    def test_web_endpoint_defaults(self) -> None:
        """Test WebEndpoint default optional fields."""
        endpoint = WebEndpoint(
            url="http://10.10.10.5/index.html",
            status_code=200,
            content_length=10918,
        )
        assert endpoint.content_type == ""
        assert endpoint.redirect_url == ""


class TestGobusterWrapper:
    """Tests for GobusterWrapper class."""

    def test_parse_output_basic(self) -> None:
        """Test parsing basic gobuster output."""
        wrapper = GobusterWrapper()
        endpoints = wrapper._parse_output(
            SAMPLE_GOBUSTER_OUTPUT,
            "http://10.10.10.5",
        )
        # Should include 200, 301, 302, 403 but NOT 404
        valid_statuses = {200, 301, 302, 403}
        for ep in endpoints:
            assert ep.status_code in valid_statuses

    def test_parse_output_filters_404(self) -> None:
        """Test that 404 responses are filtered out."""
        wrapper = GobusterWrapper()
        endpoints = wrapper._parse_output(
            SAMPLE_GOBUSTER_OUTPUT,
            "http://10.10.10.5",
        )
        status_codes = [ep.status_code for ep in endpoints]
        assert 404 not in status_codes

    def test_parse_output_counts(self) -> None:
        """Test correct count of parsed endpoints."""
        wrapper = GobusterWrapper()
        endpoints = wrapper._parse_output(
            SAMPLE_GOBUSTER_OUTPUT,
            "http://10.10.10.5",
        )
        # 5 valid endpoints (200x3, 301x1, 403x1, 302x1)
        # /index.html(200), /images(301), /login(200),
        # /admin(403), /config.php(302), /secret(200)
        assert len(endpoints) == 6

    def test_gobuster_result_total_count(self) -> None:
        """Test GobusterResult total_found matches endpoints."""
        result = GobusterResult(
            target_url="http://10.10.10.5",
            endpoints=[
                WebEndpoint(
                    url="http://10.10.10.5/index.html",
                    status_code=200,
                    content_length=10918,
                ),
                WebEndpoint(
                    url="http://10.10.10.5/admin",
                    status_code=403,
                    content_length=277,
                ),
            ],
            scan_duration_seconds=15.3,
            wordlist_used="/usr/share/wordlists/dirb/common.txt",
            total_found=2,
        )
        assert result.total_found == len(result.endpoints)

    def test_wrapper_initialization(self) -> None:
        """Test GobusterWrapper initializes with defaults."""
        wrapper = GobusterWrapper()
        assert wrapper._wordlist == "/usr/share/wordlists/dirb/common.txt"
        assert wrapper._threads == 10
        assert wrapper._timeout == 300

    def test_wrapper_custom_config(self) -> None:
        """Test GobusterWrapper accepts custom configuration."""
        wrapper = GobusterWrapper(
            wordlist="/custom/wordlist.txt",
            threads=20,
            timeout=600,
        )
        assert wrapper._wordlist == "/custom/wordlist.txt"
        assert wrapper._threads == 20
        assert wrapper._timeout == 600
