"""Verification Agent — validates exploit success and generates post-mortems.

Implements Week 15–16 deliverables for Member C (Vedant):
- Session confirmation via Metasploit ``sessions.list``
- Privilege check via ``id`` command executed inside the session
- Structured JSON post-mortem on failure
- Writes failure edges back to the attack graph

Owner: Vedant (Member C)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from src.state.attack_graph import AttackGraph
from src.state.schemas import (
    EdgeType,
    ExploitAttempt,
    ExploitPostMortem,
    FindingCategory,
    PrivilegeLevel,
    SessionNode,
    VerifiedFinding,
)
from src.tools.metasploit_rpc import (
    MetasploitRPCClient,
    MetasploitRPCError,
    SessionInfo,
)
from src.validators.base import ValidationOutcome
from src.validators.registry import ValidatorRegistry, default_registry

logger = logging.getLogger(__name__)

# Regex patterns for privilege detection from `id` output
_ROOT_PATTERN = re.compile(r"uid=0\(root\)|uid=0\b")
_USER_PATTERN = re.compile(r"uid=\d+\(([^)]+)\)")

# Privilege check command
_PRIV_CHECK_CMD = "id"

# How long to wait (seconds) for the `id` command to return output
_SESSION_CMD_TIMEOUT_SECS = 5


@dataclass
class VerificationResult:
    """Outcome of a verification run against a single exploit attempt.

    Attributes:
        attempt: The original exploit attempt that was verified.
        success: Whether the capability / finding was confirmed.
        privilege: Privilege level of the confirmed session/finding.
        session_id: Numeric Metasploit session ID if found.
        finding: Structured VerifiedFinding object if verified.
        category: Capability category string.
        evidence: Concrete proof / output evidence string.
        post_mortem: Structured post-mortem if the attempt failed.
    """

    attempt: ExploitAttempt
    success: bool = False
    privilege: str = PrivilegeLevel.NONE.value
    session_id: int | None = None
    finding: VerifiedFinding | None = None
    category: str = FindingCategory.GENERAL_VULNERABILITY.value
    evidence: str = ""
    post_mortem: ExploitPostMortem | None = None


class VerificationAgent:
    """Verifies security findings across multiple capability categories.

    Uses a pluggable ValidatorRegistry to evaluate:
    1. Remote Code Execution (interactive sessions or verified command output)
    2. Authentication & Credential Discovery (valid logins, discovered creds)
    3. Information Disclosure (metadata, user enumeration, configs)
    4. File Sharing Access (SMB, NFS, anonymous FTP)
    5. Database Access (authentication, queries, schema dumps)
    6. Web Application vulnerabilities (LFI, SQLi, panel bypass)
    7. Remote Administration Services (VNC, X11, RDP)

    Args:
        attack_graph: The shared attack graph.
        msf_client: Pre-configured, connected Metasploit RPC client.
        registry: ValidatorRegistry managing capability validators.
    """

    def __init__(
        self,
        attack_graph: AttackGraph,
        msf_client: MetasploitRPCClient | None = None,
        registry: ValidatorRegistry | None = None,
    ) -> None:
        """Initialise the VerificationAgent."""
        self._graph = attack_graph
        self._msf = msf_client
        self._registry = registry or default_registry

    # ── Public API ────────────────────────────────────────────────

    def verify(self, attempt: ExploitAttempt) -> ExploitAttempt:
        """Verify a single exploit attempt and return the updated record.

        This is the backwards-compatible entry point used by the
        orchestrator's ``verify_node``.

        Args:
            attempt: The exploit attempt to verify.

        Returns:
            The (possibly updated) :class:`ExploitAttempt`.
        """
        result = self.verify_attempt(attempt)
        return result.attempt

    def verify_attempt(self, attempt: ExploitAttempt) -> VerificationResult:
        """Full pluggable verification pipeline for an exploit attempt.

        Args:
            attempt: The exploit attempt to verify.

        Returns:
            A :class:`VerificationResult` with all verification details.
        """
        logger.info(
            "Verifying exploit attempt: module=%s target=%s",
            attempt.module_used,
            attempt.target_service_id,
        )

        target_ip = self._extract_target_ip(attempt.target_service_id)

        # Context for validation
        context = {
            "session_id": attempt.session_id,
            "target_service_id": attempt.target_service_id,
            "payload": attempt.payload,
            "error_type": attempt.error_type,
            "raw_error": attempt.raw_error,
        }
        raw_payload = attempt.evidence or attempt.raw_error or attempt.result

        # If no MSF client is available (testing / recon-only mode)
        if self._msf is None or not self._msf.is_connected():
            logger.debug(
                "Evaluating attempt via offline validator registry (session_id=%s)",
                attempt.session_id,
            )
            outcome = self._registry.validate(
                target=target_ip,
                service_id=attempt.target_service_id,
                module_path=attempt.module_used,
                raw_output=raw_payload,
                msf_client=None,
                context=context,
            )
            if outcome.is_valid:
                return self._record_successful_verification(attempt, outcome, target_ip)
            if attempt.result == "success" and attempt.session_id:
                return self._no_msf_verify(attempt)
            return self._handle_failure(attempt, reason=attempt.error_type or "validation_failed")

        # ── Step 1: Pluggable Capability Validation ──────────────────
        outcome = self._registry.validate(
            target=target_ip,
            service_id=attempt.target_service_id,
            module_path=attempt.module_used,
            raw_output=raw_payload,
            msf_client=self._msf,
            context=context,
        )

        if outcome.is_valid:
            return self._record_successful_verification(attempt, outcome, target_ip)

        # ── Step 2: Handle Validation Failure ────────────────────────
        attempt.result = "failure"
        attempt.error_type = outcome.error_type or attempt.error_type or "validation_failed"
        return self._handle_failure(
            attempt,
            reason=attempt.error_type,
        )

    def _record_successful_verification(
        self,
        attempt: ExploitAttempt,
        outcome: ValidationOutcome,
        target_ip: str,
    ) -> VerificationResult:
        """Record verified finding and active session (if any) in the attack graph."""
        import uuid

        # Update attempt fields
        attempt.result = "success"
        attempt.finding_category = outcome.category.value
        attempt.evidence = outcome.evidence
        if outcome.session_id is not None:
            attempt.session_id = str(outcome.session_id)

        # Create VerifiedFinding
        finding_id = f"{outcome.category.value}_{uuid.uuid4().hex[:8]}"
        port = 0
        if ":" in attempt.target_service_id:
            try:
                parts = attempt.target_service_id.split(":")
                if len(parts) >= 3 and "/" in parts[2]:
                    port = int(parts[2].split("/")[0])
            except Exception:
                port = 0

        finding = VerifiedFinding(
            finding_id=finding_id,
            category=outcome.category.value,
            title=outcome.title or f"Verified {outcome.category.value.replace('_', ' ').title()}",
            description=outcome.description,
            evidence=outcome.evidence,
            target_service_id=attempt.target_service_id,
            host_ip=target_ip,
            port=port,
            module_used=attempt.module_used,
            session_id=str(outcome.session_id) if outcome.session_id is not None else "",
        )
        self._graph.add_verified_finding(finding)

        # If a live session was established, update session node in graph
        if outcome.session_id is not None and self._msf is not None:
            session_info = self._find_session(target_ip)
            if session_info is not None:
                self._update_session_node(session_info, outcome.privilege)

        logger.info(
            "VERIFIED FINDING [%s]: %s on %s (privilege=%s, session=%s)",
            outcome.category.value,
            outcome.title,
            target_ip,
            outcome.privilege,
            outcome.session_id,
        )

        return VerificationResult(
            attempt=attempt,
            success=True,
            privilege=outcome.privilege,
            session_id=outcome.session_id,
            finding=finding,
            category=outcome.category.value,
            evidence=outcome.evidence,
        )

    # ── Internal helpers ──────────────────────────────────────────

    def _find_session(self, target_ip: str) -> SessionInfo | None:
        """Query Metasploit for an active session on *target_ip*.

        Args:
            target_ip: IP address of the target host.

        Returns:
            The matching :class:`SessionInfo`, or ``None`` if not found.
        """
        assert self._msf is not None
        try:
            sessions = self._msf.list_sessions()
            for s in sessions:
                if s.target_host == target_ip:
                    logger.info(
                        "Session %d confirmed on %s via %s",
                        s.session_id,
                        target_ip,
                        s.via_exploit,
                    )
                    return s
        except MetasploitRPCError as exc:
            logger.error("Failed to list sessions: %s", exc)
        return None

    def _check_privilege(self, session_id: int) -> str:
        """Run ``id`` inside a session to determine privilege level.

        Args:
            session_id: Numeric Metasploit session identifier.

        Returns:
            ``'root'``, ``'user'``, or ``'none'``.
        """
        assert self._msf is not None
        try:
            output = self._msf.run_session_command(session_id, _PRIV_CHECK_CMD)
            logger.debug("Privilege check output (session %d): %r", session_id, output)

            if _ROOT_PATTERN.search(output):
                logger.info("PRIVILEGE: root — session %d", session_id)
                return PrivilegeLevel.ROOT.value

            if _USER_PATTERN.search(output):
                logger.info("PRIVILEGE: user — session %d", session_id)
                return PrivilegeLevel.USER.value

        except MetasploitRPCError as exc:
            logger.warning(
                "Privilege check failed for session %d: %s",
                session_id,
                exc,
            )

        return PrivilegeLevel.NONE.value

    def _update_session_node(self, session: SessionInfo, privilege: str) -> None:
        """Update or create a session node in the attack graph.

        Args:
            session: The confirmed session info from Metasploit.
            privilege: Determined privilege level string.
        """
        node_id = f"session:{session.session_id}"
        if self._graph.graph.has_node(node_id):
            self._graph.graph.nodes[node_id]["privilege"] = privilege
        else:
            session_node = SessionNode(
                session_id=str(session.session_id),
                host_ip=session.target_host,
                privilege=privilege,
                shell_type=session.session_type,
            )
            self._graph.graph.add_node(node_id, **session_node.to_dict())
        self._graph.persistence.save_graph(self._graph.graph)
        logger.debug("Session node updated: %s privilege=%s", node_id, privilege)

    def audit_session(self, session_id: int) -> dict[str, Any]:
        """Perform non-destructive post-exploitation triage on a live session.

        Checks user ID, kernel version, sudo privileges, and common SUID binaries.

        Args:
            session_id: Numeric Metasploit session identifier.

        Returns:
            Dictionary of audit findings.
        """
        findings: dict[str, Any] = {
            "privilege": PrivilegeLevel.NONE.value,
            "kernel": "",
            "sudo_l": "",
            "suid_binaries": [],
        }
        if self._msf is None:
            return findings

        # 1. Privilege check
        priv = self._check_privilege(session_id)
        findings["privilege"] = priv

        # 2. Kernel check
        try:
            uname_out = self._msf.run_session_command(session_id, "uname -a")
            findings["kernel"] = uname_out.strip()
        except Exception:
            pass

        # 3. Sudo -l check
        try:
            sudo_out = self._msf.run_session_command(session_id, "sudo -l -n")
            if "NOPASSWD" in sudo_out or "(ALL)" in sudo_out:
                findings["sudo_l"] = sudo_out.strip()
        except Exception:
            pass

        return findings

    def _handle_failure(
        self,
        attempt: ExploitAttempt,
        reason: str = "unknown",
    ) -> VerificationResult:
        """Generate a post-mortem and write a negative edge to the graph.

        Args:
            attempt: The failed exploit attempt.
            reason: Short reason code for the failure.

        Returns:
            A :class:`VerificationResult` with ``success=False``.
        """
        hypothesis = self._build_hypothesis(attempt.error_type or reason)
        action = self._recommend_action(attempt.error_type or reason)

        pm = ExploitPostMortem(
            target_service=attempt.target_service_id,
            module_used=attempt.module_used,
            error_type=attempt.error_type or reason,
            raw_error=attempt.raw_error,
            hypothesis=hypothesis,
            recommended_action=action,
        )

        # Write negative edge to attack graph
        self._write_failure_edge(attempt, pm)

        # Persist post-mortem record
        self._graph.record_post_mortem(pm)

        logger.info(
            "Post-mortem generated: %s → %s (action=%s)",
            attempt.module_used,
            pm.error_type,
            pm.recommended_action,
        )
        return VerificationResult(
            attempt=attempt,
            success=False,
            post_mortem=pm,
        )

    def _write_failure_edge(
        self,
        attempt: ExploitAttempt,
        pm: ExploitPostMortem,
    ) -> None:
        """Add a negative edge to the attack graph for a failed exploit.

        Args:
            attempt: The failed exploit attempt.
            pm: The post-mortem describing the failure.
        """
        failure_node_id = f"failure:{attempt.module_used}:{attempt.target_service_id}"
        # Ensure failure node exists
        if not self._graph.graph.has_node(failure_node_id):
            self._graph.graph.add_node(
                failure_node_id,
                node_type="failure",
                module=attempt.module_used,
                error_type=pm.error_type,
                hypothesis=pm.hypothesis,
            )
        # Add negative edge from service to failure node
        if self._graph.graph.has_node(attempt.target_service_id):
            self._graph.graph.add_edge(
                attempt.target_service_id,
                failure_node_id,
                type=EdgeType.EXPLOIT_ATTEMPT.value,
                result="failure",
                error_type=pm.error_type,
                post_mortem=pm.hypothesis,
            )
        self._graph.persistence.save_graph(self._graph.graph)

    def _no_msf_verify(self, attempt: ExploitAttempt) -> VerificationResult:
        """Fallback verification when no MSF client is connected.

        Used during testing and recon-only mode. Trusts the attempt
        result as-is rather than querying a live session.

        Args:
            attempt: The exploit attempt to verify.

        Returns:
            A :class:`VerificationResult` based on the attempt's stated result.
        """
        if attempt.result == "success":
            logger.info(
                "No-MSF verify: accepting exploit agent success for %s",
                attempt.module_used,
            )
            return VerificationResult(
                attempt=attempt,
                success=True,
                privilege=PrivilegeLevel.USER.value,
            )
        return self._handle_failure(attempt, reason=attempt.error_type or "unknown")

    @staticmethod
    def _extract_target_ip(service_id: str) -> str:
        """Extract the host IP from a service node ID.

        Service node IDs have the format ``service:<ip>:<port>/<proto>``.

        Args:
            service_id: Service node identifier.

        Returns:
            The extracted IP string, or the original string if parsing fails.
        """
        parts = service_id.split(":")
        if len(parts) >= 2:
            return parts[1]
        return service_id

    @staticmethod
    def _build_hypothesis(error_type: str) -> str:
        """Return a human-readable hypothesis string for an error type.

        Args:
            error_type: Short error type code.

        Returns:
            A hypothesis string suitable for reporting.
        """
        hypotheses: dict[str, str] = {
            "no_session": (
                "Exploit executed but no session was established. "
                "The service may be patched, the payload may be "
                "incompatible, or a firewall is blocking the reverse "
                "connection."
            ),
            "no_session_after_exploit": (
                "Exploit agent reported success but Metasploit confirms "
                "no active session for this target. The exploit likely "
                "ran without establishing a persistent callback."
            ),
            "exploit_reported_failure": (
                "Exploit execution failed before a session could be "
                "attempted. Check module compatibility with the target "
                "service version."
            ),
            "timeout": (
                "Exploit timed out waiting for a callback. The target "
                "may be unreachable, rate-limited, or the LHOST/LPORT "
                "configuration may be incorrect."
            ),
            "connection_refused": (
                "The Metasploit RPC daemon is unreachable or the target "
                "port is closed. Verify msfrpcd is running."
            ),
            "auth_failed": (
                "Authentication failed — credentials or payload encoding "
                "may be incorrect for this target."
            ),
            "module_not_found": (
                "The suggested module does not exist in the current "
                "Metasploit installation. This is likely an LLM "
                "hallucination — validate module paths before execution."
            ),
        }
        return hypotheses.get(
            error_type, f"Unclassified failure: error_type='{error_type}'"
        )

    @staticmethod
    def _recommend_action(error_type: str) -> str:
        """Return a recommended next action given an error type.

        Args:
            error_type: Short error type code.

        Returns:
            One of the recognised action strings.
        """
        action_map: dict[str, str] = {
            "no_session": "retry_different_payload",
            "no_session_after_exploit": "try_alternative_module",
            "exploit_reported_failure": "try_alternative_module",
            "timeout": "retry_different_payload",
            "connection_refused": "skip_service",
            "auth_failed": "retry_different_payload",
            "module_not_found": "try_alternative_module",
        }
        return action_map.get(error_type, "manual_review")
