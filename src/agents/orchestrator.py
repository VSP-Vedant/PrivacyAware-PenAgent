"""src/agents/orchestrator.py — LangGraph state machine.

Owner: Vighnesh (Member B)
"""

from __future__ import annotations

import os
from typing import Literal

from langgraph.graph import StateGraph, END
from src.state.schemas import PenTestState, ExploitAttempt
from src.state.attack_graph import AttackGraph
from src.agents.recon_agent import execute_recon
from src.agents.exploit_agent import attempt_exploit
from src.agents.verification_agent import verify_exploit
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)

def recon_node(state: PenTestState) -> PenTestState:
    logger.info("Executing recon node")
    state["current_phase"] = "recon"
    
    target = state["target"]
    ag: AttackGraph = state["attack_graph"]
    
    result = execute_recon(target)
    
    if result.hosts:
        host_id = ag.add_host(result.hosts[0])
        for svc in result.services:
            svc_id = ag.add_service(host_id, svc)
            # Map CVEs... (simplified for skeleton)
            for cve in result.cve_candidates:
                ag.add_cve(svc_id, cve)
                
    state["step_count"] += 1
    return state

def analyze_graph_node(state: PenTestState) -> PenTestState:
    logger.info("Executing analyze_graph node")
    state["step_count"] += 1
    return state

def exploit_node(state: PenTestState) -> PenTestState:
    logger.info("Executing exploit node")
    state["current_phase"] = "exploit"
    ag: AttackGraph = state["attack_graph"]
    
    exploitable = ag.get_exploitable_services()
    if not exploitable:
        logger.warning("No exploitable services found")
        return state
        
    # Just grab the first one for MVP
    svc_data = exploitable[0]
    svc_info = svc_data["data"]
    svc_id = svc_data["id"]
    
    cves = ag.get_cve_candidates(svc_id)
    failures = ag.get_failed_exploits(svc_id)
    
    attempt = attempt_exploit(state["target"], {"name": svc_info.name, "version": svc_info.version}, cves, failures)
    
    if attempt:
        state["exploit_attempts"].append(attempt)
        
    state["step_count"] += 1
    return state

def verify_node(state: PenTestState) -> PenTestState:
    logger.info("Executing verify node")
    state["current_phase"] = "verify"
    
    if not state["exploit_attempts"]:
        return state
        
    last_attempt = state["exploit_attempts"][-1]
    if last_attempt.result == "pending":
        verified = verify_exploit(last_attempt)
        state["exploit_attempts"][-1] = verified
        
        ag: AttackGraph = state["attack_graph"]
        # Simplified: assume we have cve_id mapped somewhere
        cve_id = "cve_unknown" 
        
        if verified.result == "success" and verified.session_id:
            # Need actual session info in real impl
            from src.state.schemas import SessionInfo
            ag.add_session(cve_id, SessionInfo(session_id=verified.session_id, privilege="user", shell_type="cmd"), verified)
        elif verified.result == "failure":
            ag.add_failed_exploit(cve_id, verified)
            
    state["step_count"] += 1
    return state

def replan_node(state: PenTestState) -> PenTestState:
    logger.info("Executing replan node")
    state["step_count"] += 1
    return state

def report_node(state: PenTestState) -> PenTestState:
    logger.info("Executing report node")
    state["current_phase"] = "report"
    state["step_count"] += 1
    return state

def has_exploitable(state: PenTestState) -> Literal["exploit", "report"]:
    ag: AttackGraph = state["attack_graph"]
    if ag.get_exploitable_services():
        return "exploit"
    return "report"

def check_success(state: PenTestState) -> Literal["report", "replan"]:
    if not state["exploit_attempts"]:
        return "report"
        
    last = state["exploit_attempts"][-1]
    if last.result == "success":
        return "report"
        
    # Check max retries
    if len(state["exploit_attempts"]) >= state["max_steps"]:
        return "report"
        
    return "replan"

def build_graph() -> StateGraph:
    """Build and compile the LangGraph."""
    workflow = StateGraph(PenTestState)
    
    workflow.add_node("recon", recon_node)
    workflow.add_node("analyze_graph", analyze_graph_node)
    workflow.add_node("exploit", exploit_node)
    workflow.add_node("verify", verify_node)
    workflow.add_node("replan", replan_node)
    workflow.add_node("report", report_node)
    
    workflow.set_entry_point("recon")
    workflow.add_edge("recon", "analyze_graph")
    
    workflow.add_conditional_edges("analyze_graph", has_exploitable)
    
    workflow.add_edge("exploit", "verify")
    
    workflow.add_conditional_edges("verify", check_success)
    
    workflow.add_edge("replan", "exploit")
    workflow.add_edge("report", END)
    
    return workflow.compile()
