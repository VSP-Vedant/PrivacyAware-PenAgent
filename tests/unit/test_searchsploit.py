"""Unit tests for SearchSploit wrapper module."""

from __future__ import annotations

import json

import pytest

from src.tools.searchsploit import (
    ExploitResult,
    SearchSploitError,
    SearchSploitResult,
    SearchSploitWrapper,
)


SAMPLE_SEARCHSPLOIT_JSON = json.dumps(
    {
        "RESULTS_EXPLOIT": [
            {
                "Title": "Apache 2.4.49 - Path Traversal (CVE-2021-41773)",
                "EDB-ID": "50383",
                "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py",
                "Platform": "Multiple",
                "Type": "webapps",
            },
            {
                "Title": "Apache 2.4.50 - Remote Code Execution (CVE-2021-42013)",
                "EDB-ID": "50406",
                "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50406.sh",
                "Platform": "Multiple",
                "Type": "webapps",
            },
            {
                "Title": "OpenSSH 8.7 - Username Enumeration",
                "EDB-ID": "50614",
                "Path": "/usr/share/exploitdb/exploits/linux/remote/50614.py",
                "Platform": "Linux",
                "Type": "remote",
            },
        ],
        "RESULTS_SHELLCODE": [],
    }
)

SAMPLE_SEARCHSPLOIT_EMPTY = json.dumps(
    {
        "RESULTS_EXPLOIT": [],
        "RESULTS_SHELLCODE": [],
    }
)


class TestExploitResult:
    """Tests for ExploitResult dataclass."""

    def test_exploit_result_creation(self) -> None:
        """Test basic ExploitResult instantiation."""
        result = ExploitResult(
            title="Apache 2.4.49 - Path Traversal",
            edb_id="50383",
            path="/usr/share/exploitdb/exploits/multiple/webapps/50383.py",
            platform="Multiple",
            exploit_type="webapps",
        )
        assert result.title == "Apache 2.4.49 - Path Traversal"
        assert result.edb_id == "50383"
        assert result.platform == "Multiple"
        assert result.exploit_type == "webapps"

    def test_exploit_result_fields(self) -> None:
        """Test all ExploitResult fields are accessible."""
        result = ExploitResult(
            title="OpenSSH 8.7 - Username Enumeration",
            edb_id="50614",
            path="/usr/share/exploitdb/exploits/linux/remote/50614.py",
            platform="Linux",
            exploit_type="remote",
        )
        assert "50614" in result.path
        assert result.platform == "Linux"


class TestSearchSploitWrapper:
    """Tests for SearchSploitWrapper class."""

    def test_parse_json_output(self) -> None:
        """Test parsing searchsploit JSON output."""
        wrapper = SearchSploitWrapper()
        results = wrapper._parse_json_output(SAMPLE_SEARCHSPLOIT_JSON)
        assert len(results) == 3
        assert results[0].edb_id == "50383"
        assert results[1].edb_id == "50406"
        assert results[2].edb_id == "50614"

    def test_parse_json_empty(self) -> None:
        """Test parsing empty searchsploit results."""
        wrapper = SearchSploitWrapper()
        results = wrapper._parse_json_output(SAMPLE_SEARCHSPLOIT_EMPTY)
        assert len(results) == 0

    def test_parse_json_fields_mapped(self) -> None:
        """Test that JSON fields are correctly mapped."""
        wrapper = SearchSploitWrapper()
        results = wrapper._parse_json_output(SAMPLE_SEARCHSPLOIT_JSON)
        first = results[0]
        assert "Apache" in first.title
        assert "CVE-2021-41773" in first.title
        assert first.platform == "Multiple"
        assert first.exploit_type == "webapps"

    def test_search_sploit_result_count(self) -> None:
        """Test SearchSploitResult total_found matches."""
        wrapper = SearchSploitWrapper()
        results = wrapper._parse_json_output(SAMPLE_SEARCHSPLOIT_JSON)
        search_result = SearchSploitResult(
            query="apache 2.4",
            results=results,
            total_found=len(results),
        )
        assert search_result.total_found == 3
        assert search_result.query == "apache 2.4"

    def test_parse_json_invalid(self) -> None:
        """Test parsing invalid JSON raises SearchSploitError."""
        wrapper = SearchSploitWrapper()
        with pytest.raises(SearchSploitError):
            wrapper._parse_json_output("not valid json")
