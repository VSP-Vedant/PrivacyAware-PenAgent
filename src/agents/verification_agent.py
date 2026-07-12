"""Verification Agent (Stub) — validates if an exploit succeeded.

Owner: Parth (Member D) — Scheduled for Weeks 15-16.
Stubbed for MVP integration.
"""

from __future__ import annotations

import logging

from src.state.schemas import ExploitAttempt, ExploitPostMortem
from src.state.attack_graph import AttackGraph

logger = logging.getLogger(__name__)


class VerificationAgent:
    """Stub for the Verification Agent.
    
    In Phase 3, this will run `sessions.list` and `id` to verify 
    if a session is valid, and use the LLM to generate post-mortems 
    on failure.
    """
    
    def __init__(self, attack_graph: AttackGraph) -> None:
        self._graph = attack_graph
        
    def verify(self, attempt: ExploitAttempt) -> ExploitAttempt:
        """Mock verification."""
        logger.info("Mock verifying attempt: %s", attempt.module_used)
        
        # If the exploit agent thought it succeeded, we just agree for now
        if attempt.result == "success" and not attempt.session_id:
            attempt.session_id = "mock_session_1"
            
        return attempt
