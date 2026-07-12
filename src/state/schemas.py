"""Data schemas for PrivacyAware-PenAgent attack graph.

Defines the dataclass models for all node and edge types stored
in the attack graph: hosts, services, CVEs, sessions, and
exploit attempts.

Owner: Parth (Member D)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TypedDict


class NodeType(Enum):
    """Types of nodes in the attack graph."""

    HOST = "host"
    SERVICE = "service"
    WEB_ENDPOINT = "web_endpoint"
    CVE = "cve"
    SESSION = "session"


class EdgeType(Enum):
    """Types of edges (relationships) in the attack graph."""

    HOSTS_SERVICE = "hosts_service"
    HAS_ENDPOINT = "has_endpoint"
    VULNERABLE_TO = "vulnerable_to"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    ESCALATED_TO = "escalated_to"


class PrivilegeLevel(Enum):
    """Privilege levels for sessions."""

    NONE = "none"
    USER = "user"
    ROOT = "root"


class ExploitResult(Enum):
    """Possible outcomes of an exploit attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


class ErrorType(Enum):
    """Types of exploit failure errors."""

    NO_SESSION = "no_session"
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    AUTH_FAILED = "auth_failed"
    MODULE_NOT_FOUND = "module_not_found"


def _utc_now() -> str:
    """Return current UTC timestamp as ISO format string."""
    return datetime.now(timezone.utc).isoformat()


# ── Node Schemas ─────────────────────────────────────────────


@dataclass
class HostNode:
    """A discovered host (machine) on the network.

    Attributes:
        ip: IPv4 address of the host.
        hostname: Resolved hostname, empty if unknown.
        os_guess: Best OS detection guess from Nmap.
        status: Host status, typically 'up' or 'down'.
        discovered_at: ISO timestamp when host was first discovered.
    """

    ip: str
    hostname: str = ""
    os_guess: str = ""
    status: str = "up"
    discovered_at: str = field(default_factory=_utc_now)

    @property
    def node_id(self) -> str:
        """Generate unique node ID for the attack graph."""
        return f"host:{self.ip}"

    @property
    def node_type(self) -> NodeType:
        """Return the node type enum."""
        return NodeType.HOST

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for graph storage."""
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["node_id"] = self.node_id
        return data


@dataclass
class ServiceNode:
    """A network service running on a host.

    Attributes:
        host_ip: IP of the host running this service.
        port: Port number the service listens on.
        protocol: Network protocol, typically 'tcp' or 'udp'.
        name: Service name (e.g., 'ssh', 'http', 'ftp').
        version: Service version string from banner grab.
        state: Port state, typically 'open'.
        product: Software product name (e.g., 'OpenSSH').
        extra_info: Additional info from Nmap scripts.
        discovered_at: ISO timestamp when service was discovered.
    """

    host_ip: str
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    version: str = ""
    state: str = "open"
    product: str = ""
    extra_info: str = ""
    discovered_at: str = field(default_factory=_utc_now)

    @property
    def node_id(self) -> str:
        """Generate unique node ID for the attack graph."""
        return f"service:{self.host_ip}:{self.port}/{self.protocol}"

    @property
    def node_type(self) -> NodeType:
        """Return the node type enum."""
        return NodeType.SERVICE

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for graph storage."""
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["node_id"] = self.node_id
        return data


@dataclass
class WebEndpointNode:
    """A discovered web endpoint from directory brute-forcing.

    Attributes:
        host_ip: IP of the host serving this endpoint.
        port: Port number of the web service.
        url: Full URL path of the endpoint.
        status_code: HTTP response status code.
        content_type: HTTP Content-Type header value.
        discovered_at: ISO timestamp when endpoint was discovered.
    """

    host_ip: str
    port: int
    url: str
    status_code: int = 200
    content_type: str = ""
    discovered_at: str = field(default_factory=_utc_now)

    @property
    def node_id(self) -> str:
        """Generate unique node ID for the attack graph."""
        return f"web:{self.host_ip}:{self.port}{self.url}"

    @property
    def node_type(self) -> NodeType:
        """Return the node type enum."""
        return NodeType.WEB_ENDPOINT

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for graph storage."""
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["node_id"] = self.node_id
        return data


@dataclass
class CVENode:
    """A known vulnerability (CVE) associated with a service.

    Attributes:
        cve_id: CVE identifier (e.g., 'CVE-2021-44228').
        cvss_score: CVSS severity score (0.0 to 10.0).
        description: Brief description of the vulnerability.
        exploitdb_ref: ExploitDB reference ID, empty if none.
        discovered_at: ISO timestamp when CVE was mapped.
    """

    cve_id: str
    cvss_score: float = 0.0
    description: str = ""
    exploitdb_ref: str = ""
    discovered_at: str = field(default_factory=_utc_now)

    @property
    def node_id(self) -> str:
        """Generate unique node ID for the attack graph."""
        return f"cve:{self.cve_id}"

    @property
    def node_type(self) -> NodeType:
        """Return the node type enum."""
        return NodeType.CVE

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for graph storage."""
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["node_id"] = self.node_id
        return data


@dataclass
class SessionNode:
    """An active shell session obtained through exploitation.

    Attributes:
        session_id: Metasploit session identifier.
        host_ip: IP of the compromised host.
        privilege: Privilege level of the session.
        shell_type: Type of shell (e.g., 'meterpreter', 'shell').
        opened_at: ISO timestamp when session was opened.
    """

    session_id: str
    host_ip: str
    privilege: str = "user"
    shell_type: str = "shell"
    opened_at: str = field(default_factory=_utc_now)

    @property
    def node_id(self) -> str:
        """Generate unique node ID for the attack graph."""
        return f"session:{self.session_id}"

    @property
    def node_type(self) -> NodeType:
        """Return the node type enum."""
        return NodeType.SESSION

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for graph storage."""
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["node_id"] = self.node_id
        return data


# ── Edge / Record Schemas ────────────────────────────────────


@dataclass
class ExploitAttempt:
    """Record of a single exploit attempt against a service.

    Attributes:
        target_service_id: Node ID of the targeted service.
        module_used: Metasploit module path used.
        payload: Payload used in the exploit.
        result: Outcome of the attempt.
        session_id: Session ID if successful, empty if failed.
        error_type: Type of error if failed, empty if successful.
        raw_error: Raw error message from the tool.
        timestamp: ISO timestamp of the attempt.
    """

    target_service_id: str
    module_used: str
    payload: str = ""
    result: str = "failure"
    session_id: str = ""
    error_type: str = ""
    raw_error: str = ""
    timestamp: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)


@dataclass
class ExploitPostMortem:
    """Structured analysis of a failed exploit attempt.

    Generated by the Verification Agent to help the Orchestrator
    decide what to try next.

    Attributes:
        target_service: Description of the targeted service.
        module_used: Metasploit module path that was tried.
        error_type: Category of the failure.
        raw_error: Raw error output from the tool.
        hypothesis: LLM-generated root cause hypothesis.
        recommended_action: What the agent should try next.
        timestamp: ISO timestamp of the post-mortem.
    """

    target_service: str
    module_used: str
    error_type: str = "no_session"
    raw_error: str = ""
    hypothesis: str = ""
    recommended_action: str = "retry_different_payload"
    timestamp: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)


class PenTestState(TypedDict):
    """LangGraph state dictionary.

    This is the state object that is passed between nodes in the LangGraph.
    """

    target: str
    attack_graph: Any  # Actually AttackGraph, but avoiding circular import
    current_phase: str
    exploit_attempts: list[ExploitAttempt]
    sessions: list[SessionNode]
    step_count: int
    max_steps: int
    cloud_tokens_used: int
    findings: list[dict[str, Any]]
