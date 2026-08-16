"""Unit tests for WebScanner wrapper."""

from unittest.mock import MagicMock, patch
import pytest
import requests

from src.state.schemas import CVENode, WebEndpointNode
from src.tools.web_scanner import WebScanner, WebScanResult
from src.utils.validators import TargetValidationError


class TestWebScanner:
    """Unit tests for WebScanner class."""

    def test_target_validation_blocks_disallowed(self) -> None:
        """Verify scan_service raises TargetValidationError on public IP."""
        scanner = WebScanner()
        with pytest.raises(TargetValidationError):
            scanner.scan_service("8.8.8.8", 80)

    @patch("requests.Session.get")
    def test_scan_service_success(self, mock_get: MagicMock) -> None:
        """Verify scan_service processes base URL and high-priority endpoints."""
        # Mock base URL response
        mock_base_resp = MagicMock()
        mock_base_resp.status_code = 200
        mock_base_resp.headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
            "Content-Type": "text/html",
        }
        mock_base_resp.text = "<html>Welcome to Admin Portal</html>"

        # Mock probe responses
        mock_admin_resp = MagicMock()
        mock_admin_resp.status_code = 200
        mock_admin_resp.headers = {"Content-Type": "text/html"}
        mock_admin_resp.text = "<h1>Login</h1>"

        def side_effect(url, **kwargs):
            if url.endswith(":80"):
                return mock_base_resp
            if "/admin" in url:
                return mock_admin_resp
            mock_404 = MagicMock()
            mock_404.status_code = 404
            return mock_404

        mock_get.side_effect = side_effect

        scanner = WebScanner(timeout_secs=1.0)
        result = scanner.scan_service(
            "10.10.10.10", 80, protocol="http", vhost="target.htb"
        )

        assert result.target == "10.10.10.10"
        assert result.port == 80
        assert any("Apache/2.4.41" in tech for tech in result.technologies)
        assert any("PHP/7.4.3" in tech for tech in result.technologies)
        assert len(result.endpoints) >= 1
        assert any("/admin" in ep.url for ep in result.endpoints)

    @patch("requests.Session.get")
    def test_scan_service_exposed_git_cve(self, mock_get: MagicMock) -> None:
        """Verify exposed .git repository detection generates a CVENode."""
        mock_git_resp = MagicMock()
        mock_git_resp.status_code = 200
        mock_git_resp.headers = {"Content-Type": "text/plain"}
        mock_git_resp.text = "ref: refs/heads/master"

        def side_effect(url, **kwargs):
            if "/.git/HEAD" in url:
                return mock_git_resp
            mock_404 = MagicMock()
            mock_404.status_code = 404
            return mock_404

        mock_get.side_effect = side_effect

        scanner = WebScanner(timeout_secs=1.0)
        result = scanner.scan_service("192.168.0.12", 80)

        assert any(cve.cve_id == "MISC-EXPOSED-GIT" for cve in result.cves)
