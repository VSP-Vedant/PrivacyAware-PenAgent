"""Unit tests for ReconAgent — full reconnaissance pipeline.

Tests the Nmap → Gobuster → CVE mapping pipeline using
mocked tool wrappers and a real in-memory attack graph.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agents.recon_agent import ReconAgent, ReconResult
from src.state.attack_graph import AttackGraph
from src.tools.nmap_wrapper import HostInfo, NmapScanResult, ServiceInfo


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Create a temporary database path."""
    return str(tmp_path / "test_recon.db")


@pytest.fixture
def attack_graph(temp_db: str) -> AttackGraph:
    """Create a fresh AttackGraph with a temp database."""
    return AttackGraph(db_path=temp_db)


@pytest.fixture
def mock_nmap_result() -> NmapScanResult:
    """A mock Nmap scan result with typical services."""
    return NmapScanResult(
        hosts=[
            HostInfo(
                ip="10.10.10.5",
                hostname="htb-target.htb",
                os_guess="Linux 5.4",
                status="up",
            )
        ],
        services=[
            ServiceInfo(
                port=22,
                protocol="tcp",
                service="ssh",
                version="8.9p1",
                state="open",
                product="OpenSSH",
                extra_info="Ubuntu Linux; protocol 2.0",
            ),
            ServiceInfo(
                port=80,
                protocol="tcp",
                service="http",
                version="2.4.52",
                state="open",
                product="Apache httpd",
                extra_info="(Ubuntu)",
            ),
            ServiceInfo(
                port=443,
                protocol="tcp",
                service="https",
                version="1.18.0",
                state="open",
                product="nginx",
                extra_info="(Ubuntu)",
            ),
        ],
        os_guess="Linux 5.4",
        scan_duration_seconds=59.0,
        raw_xml_path=None,
        scan_command="nmap -sV -sC 10.10.10.5",
    )


class TestReconAgentPipeline:
    """Tests for the full recon pipeline."""

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_full_pipeline_populates_graph(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """Full pipeline should populate graph with hosts + services."""
        # Configure mocks
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = False

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(
            attack_graph=attack_graph,
            use_gobuster=True,
            use_cve_mapping=True,
        )
        result = agent.run("10.10.10.5")

        # Verify result structure
        assert isinstance(result, ReconResult)
        assert result.target == "10.10.10.5"
        assert len(result.hosts) == 1
        assert len(result.services) == 3
        assert result.os_guess == "Linux 5.4"

        # Verify graph was populated
        assert attack_graph.graph.number_of_nodes() >= 4  # 1 host + 3 services

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_host_node_added_to_graph(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """Host node should be present in graph after recon."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = False

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(attack_graph=attack_graph)
        agent.run("10.10.10.5")

        assert attack_graph.graph.has_node("host:10.10.10.5")
        host_data = attack_graph.graph.nodes["host:10.10.10.5"]
        assert host_data["ip"] == "10.10.10.5"
        assert host_data["node_type"] == "host"

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_service_nodes_linked_to_host(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """Service nodes should be linked to their host node."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = False

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(attack_graph=attack_graph)
        agent.run("10.10.10.5")

        # Check that service nodes exist and are linked
        ssh_node = "service:10.10.10.5:22/tcp"
        assert attack_graph.graph.has_node(ssh_node)
        assert attack_graph.graph.has_edge("host:10.10.10.5", ssh_node)


class TestReconAgentGobuster:
    """Tests for Gobuster integration in the recon pipeline."""

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_gobuster_skipped_when_disabled(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """Gobuster should not run when use_gobuster=False."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(
            attack_graph=attack_graph,
            use_gobuster=False,
        )
        result = agent.run("10.10.10.5")

        mock_gb_instance.scan.assert_not_called()
        assert result.web_endpoints == []

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_gobuster_skipped_when_no_http_services(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
    ) -> None:
        """Gobuster should not run when there are no HTTP services."""
        no_http_result = NmapScanResult(
            hosts=[HostInfo(ip="10.10.10.5", hostname="", os_guess="", status="up")],
            services=[
                ServiceInfo(
                    port=22, protocol="tcp", service="ssh", version="8.9", state="open"
                ),
            ],
            os_guess=None,
            scan_duration_seconds=10.0,
            raw_xml_path=None,
            scan_command="nmap -sV 10.10.10.5",
        )
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = no_http_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = True

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(attack_graph=attack_graph)
        agent.run("10.10.10.5")

        mock_gb_instance.scan.assert_not_called()


class TestReconAgentCVEMapping:
    """Tests for CVE mapping in the recon pipeline."""

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_cve_mapping_disabled(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """CVE mapping should not run when disabled."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = False

        mock_cve_instance = MockCVEMapper.return_value

        agent = ReconAgent(
            attack_graph=attack_graph,
            use_cve_mapping=False,
        )
        result = agent.run("10.10.10.5")

        mock_cve_instance.map_services.assert_not_called()
        assert result.cve_candidates == []


class TestReconAgentGetExploitable:
    """Tests that recon results feed into get_exploitable_services()."""

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_get_exploitable_services_after_recon(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """get_exploitable_services() should return services after recon."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = False

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(attack_graph=attack_graph)
        agent.run("10.10.10.5")

        services = attack_graph.get_exploitable_services()
        assert len(services) == 3

        service_names = [s["name"] for s in services]
        assert "ssh" in service_names
        assert "http" in service_names
        assert "https" in service_names


class TestReconResult:
    """Tests for the ReconResult dataclass."""

    def test_default_recon_result(self) -> None:
        """Default ReconResult should have empty lists."""
        result = ReconResult()
        assert result.hosts == []
        assert result.services == []
        assert result.web_endpoints == []
        assert result.cve_candidates == []
        assert result.os_guess is None
        assert result.scan_duration_seconds == 0.0
        assert result.target == ""


class TestReconAgentRunFromXML:
    """Tests for ReconAgent.run_from_xml()."""

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_run_from_xml_populates_graph(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
        tmp_path: Path,
    ) -> None:
        """run_from_xml() should parse XML and populate the graph."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.parse_xml.return_value = mock_nmap_result

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        xml_path = str(tmp_path / "scan.xml")
        # Create a placeholder file so the agent accepts the path
        with open(xml_path, "w") as f:
            f.write("<nmaprun/>")

        agent = ReconAgent(
            attack_graph=attack_graph, use_gobuster=False, use_cve_mapping=True
        )
        result = agent.run_from_xml(xml_path, "10.10.10.5")

        assert result.target == "10.10.10.5"
        assert len(result.hosts) == 1
        assert len(result.services) == 3
        # Graph should have host + 3 service nodes
        assert attack_graph.graph.number_of_nodes() >= 4

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_run_from_xml_no_cve_mapping(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
        tmp_path: Path,
    ) -> None:
        """run_from_xml() with use_cve_mapping=False should skip CVE step."""
        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.parse_xml.return_value = mock_nmap_result

        mock_cve_instance = MockCVEMapper.return_value

        xml_path = str(tmp_path / "scan.xml")
        with open(xml_path, "w") as f:
            f.write("<nmaprun/>")

        agent = ReconAgent(
            attack_graph=attack_graph, use_gobuster=False, use_cve_mapping=False
        )
        result = agent.run_from_xml(xml_path, "10.10.10.5")

        mock_cve_instance.map_services.assert_not_called()
        assert result.cve_candidates == []


class TestReconAgentCVEGraphPopulation:
    """Tests for CVE node insertion and graph linking."""

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_cve_nodes_added_to_graph(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """CVE candidates should be added as nodes in the attack graph."""
        from src.tools.cve_mapper import CVECandidate, CVEMappingResult

        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = False

        # Return one CVE candidate for the ftp service
        cve_candidate = CVECandidate(
            cve_id="CVE-2011-2523",
            cvss_score=10.0,
            description="vsftpd 2.3.4 backdoor",
            source="knowledge_base",
            confidence=0.8,
        )
        mapping_result = CVEMappingResult(
            service_name="ftp",
            service_version="2.3.4",
            candidates=[cve_candidate],
            total_found=1,
        )
        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = [mapping_result]

        agent = ReconAgent(
            attack_graph=attack_graph, use_gobuster=False, use_cve_mapping=True
        )
        agent.run("10.10.10.5")

        # CVE node should exist in graph
        assert attack_graph.graph.has_node("cve:CVE-2011-2523")

    @patch("src.agents.recon_agent.NmapWrapper")
    @patch("src.agents.recon_agent.GobusterWrapper")
    @patch("src.agents.recon_agent.CVEMapper")
    def test_gobuster_endpoints_added_to_graph(
        self,
        MockCVEMapper: MagicMock,
        MockGobuster: MagicMock,
        MockNmap: MagicMock,
        attack_graph: AttackGraph,
        mock_nmap_result: NmapScanResult,
    ) -> None:
        """Gobuster-discovered endpoints should appear in the graph."""
        from src.tools.gobuster_wrapper import GobusterResult, WebEndpoint

        mock_nmap_instance = MockNmap.return_value
        mock_nmap_instance.scan.return_value = mock_nmap_result

        mock_gb_instance = MockGobuster.return_value
        mock_gb_instance.is_available.return_value = True
        mock_gb_instance.scan.return_value = GobusterResult(
            target_url="http://10.10.10.5:80",
            endpoints=[
                WebEndpoint(
                    url="http://10.10.10.5:80/admin",
                    status_code=200,
                    content_length=1024,
                )
            ],
            scan_duration_seconds=5.0,
            wordlist_used="/usr/share/wordlists/dirb/common.txt",
            total_found=1,
        )

        mock_cve_instance = MockCVEMapper.return_value
        mock_cve_instance.map_services.return_value = []

        agent = ReconAgent(
            attack_graph=attack_graph, use_gobuster=True, use_cve_mapping=False
        )
        result = agent.run("10.10.10.5")

        assert len(result.web_endpoints) >= 1
        # web endpoint node should exist
        web_nodes = [n for n in attack_graph.graph.nodes() if n.startswith("web:")]
        assert len(web_nodes) >= 1
