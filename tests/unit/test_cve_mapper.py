"""Unit tests for CVEMapper — service-version-to-CVE mapping.

Tests the curated knowledge base lookups, deduplication,
and SearchSploit fallback behaviour.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.tools.cve_mapper import CVECandidate, CVEMapper, CVEMappingResult


class TestCVEMapperKnowledgeBase:
    """Tests for the built-in CVE knowledge base."""

    def setup_method(self) -> None:
        """Create a mapper with SearchSploit disabled."""
        self.mapper = CVEMapper(use_searchsploit=False)

    def test_map_vsftpd_234_backdoor(self) -> None:
        """vsftpd 2.3.4 should map to the famous backdoor CVE."""
        result = self.mapper.map_service("ftp", "vsftpd", "2.3.4")
        assert result.total_found >= 1
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2011-2523" in cve_ids

    def test_map_apache_2449_path_traversal(self) -> None:
        """Apache 2.4.49 should map to path traversal CVEs."""
        result = self.mapper.map_service("http", "Apache", "2.4.49")
        assert result.total_found >= 1
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2021-41773" in cve_ids

    def test_map_apache_2450_rce(self) -> None:
        """Apache 2.4.50 should map to the traversal bypass."""
        result = self.mapper.map_service("http", "Apache", "2.4.50")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2021-42013" in cve_ids

    def test_map_openssh_73_agent_forwarding(self) -> None:
        """OpenSSH 7.3 should match CVE-2016-10009."""
        result = self.mapper.map_service("ssh", "OpenSSH", "7.3")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2016-10009" in cve_ids

    def test_map_openssh_82_command_injection(self) -> None:
        """OpenSSH 8.2 should match CVE-2020-15778."""
        result = self.mapper.map_service("ssh", "OpenSSH", "8.2")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2020-15778" in cve_ids

    def test_map_smb_eternalblue(self) -> None:
        """SMB/microsoft-ds should include EternalBlue."""
        result = self.mapper.map_service("microsoft-ds", "Windows", "10")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2017-0144" in cve_ids

    def test_map_unknown_service_returns_empty(self) -> None:
        """Unknown services should return no CVEs."""
        result = self.mapper.map_service("mystery-svc", "UnknownProd", "99.99")
        assert result.total_found == 0
        assert result.candidates == []

    def test_map_empty_version_no_crash(self) -> None:
        """Empty version string should not crash."""
        result = self.mapper.map_service("http", "Apache", "")
        assert isinstance(result, CVEMappingResult)

    def test_map_version_with_suffix(self) -> None:
        """Version strings with suffixes like 'p1' should still match."""
        result = self.mapper.map_service("ssh", "OpenSSH", "8.2p1")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2020-15778" in cve_ids

    def test_candidate_confidence_is_high(self) -> None:
        """Knowledge base matches should have high confidence."""
        result = self.mapper.map_service("ftp", "vsftpd", "2.3.4")
        for c in result.candidates:
            assert c.confidence >= 0.8

    def test_candidate_source_is_knowledge_base(self) -> None:
        """Knowledge base matches should report source correctly."""
        result = self.mapper.map_service("ftp", "vsftpd", "2.3.4")
        for c in result.candidates:
            assert c.source == "knowledge_base"


class TestCVEMapperDeduplication:
    """Tests for CVE candidate deduplication."""

    def setup_method(self) -> None:
        self.mapper = CVEMapper(use_searchsploit=False)

    def test_no_duplicate_cve_ids(self) -> None:
        """Results should not contain duplicate CVE IDs."""
        result = self.mapper.map_service("microsoft-ds", "Windows", "10")
        cve_ids = [c.cve_id for c in result.candidates]
        assert len(cve_ids) == len(set(cve_ids))


class TestCVEMapperBulk:
    """Tests for bulk service mapping."""

    def setup_method(self) -> None:
        self.mapper = CVEMapper(use_searchsploit=False)

    def test_map_multiple_services(self) -> None:
        """map_services should return one result per service."""
        services = [
            {"service": "ftp", "product": "vsftpd", "version": "2.3.4"},
            {"service": "ssh", "product": "OpenSSH", "version": "8.2p1"},
            {"service": "http", "product": "nginx", "version": "1.14.0"},
        ]
        results = self.mapper.map_services(services)
        assert len(results) == 3
        assert results[0].total_found >= 1  # vsftpd
        assert results[1].total_found >= 1  # OpenSSH

    def test_map_services_with_name_key(self) -> None:
        """Services using 'name' instead of 'service' key should work."""
        services = [
            {"name": "ftp", "product": "vsftpd", "version": "2.3.4"},
        ]
        results = self.mapper.map_services(services)
        assert len(results) == 1
        assert results[0].total_found >= 1


class TestCVECandidateConversion:
    """Tests for CVECandidate → CVENode conversion."""

    def test_to_cve_node(self) -> None:
        """CVECandidate.to_cve_node() should produce a valid CVENode."""
        candidate = CVECandidate(
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            description="Log4Shell",
            exploitdb_ref="EDB-50592",
            source="knowledge_base",
            confidence=0.9,
        )
        node = candidate.to_cve_node()
        assert node.cve_id == "CVE-2021-44228"
        assert node.cvss_score == 10.0
        assert node.exploitdb_ref == "EDB-50592"


class TestCVEMapperSearchSploitFallback:
    """Tests for SearchSploit fallback behaviour."""

    @patch.object(CVEMapper, "_lookup_searchsploit")
    def test_searchsploit_called_when_kb_empty(self, mock_ss: MagicMock) -> None:
        """SearchSploit should be called when KB returns nothing."""
        mock_ss.return_value = [
            CVECandidate(
                cve_id="EDB-12345",
                description="test exploit",
                source="searchsploit",
                confidence=0.5,
            )
        ]
        mapper = CVEMapper(use_searchsploit=True)
        result = mapper.map_service("mystery", "UnknownApp", "1.0")
        mock_ss.assert_called_once()
        assert result.total_found >= 1

    def test_searchsploit_not_called_when_disabled(self) -> None:
        """SearchSploit should not be called when disabled."""
        mapper = CVEMapper(use_searchsploit=False)
        result = mapper.map_service("mystery", "UnknownApp", "1.0")
        assert result.total_found == 0

    @patch.object(CVEMapper, "_lookup_searchsploit")
    def test_searchsploit_not_called_when_kb_has_results(
        self, mock_ss: MagicMock
    ) -> None:
        """SearchSploit should NOT be called when KB has results."""
        mapper = CVEMapper(use_searchsploit=True)
        mapper.map_service("ftp", "vsftpd", "2.3.4")
        mock_ss.assert_not_called()

    def test_mysql_mapping(self) -> None:
        """MySQL 5.1 should match CVE-2012-2122."""
        mapper = CVEMapper(use_searchsploit=False)
        result = mapper.map_service("mysql", "MySQL", "5.1")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2012-2122" in cve_ids

    def test_proftpd_mapping(self) -> None:
        """ProFTPD 1.3.3 should match CVE-2015-3306."""
        mapper = CVEMapper(use_searchsploit=False)
        result = mapper.map_service("ftp", "ProFTPD", "1.3.3")
        cve_ids = [c.cve_id for c in result.candidates]
        assert "CVE-2015-3306" in cve_ids
