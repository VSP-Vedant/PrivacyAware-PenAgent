"""Prompt templates for PrivacyAware-PenAgent (Member A owned).

All agent prompts defined here for consistency and easy maintenance.
Follows CLAUDE.md §2 standards.
"""

from typing import Any, Dict

PROMPTS: Dict[str, str] = {
    # Router Classification Prompt (CLAUDE.md §2.3)
    "router_classification": """You are a task classifier for a hybrid LLM routing system in a penetration testing framework.  # noqa: E501

Classify the following task on two dimensions:

1. DATA_SENSITIVITY (0.0-1.0): Does the input/output contain credentials, IPs, session tokens, file paths, or target system data?  # noqa: E501
2. REASONING_COMPLEXITY (0.0-1.0): Does this task require multi-hop inference, CVE chaining, privilege escalation reasoning, or complex decision making?  # noqa: E501

ROUTING RULES:
- If sensitivity > 0.6 OR complexity > 0.7 → recommend CLOUD (gpt-4o)
- Otherwise → recommend LOCAL (llama3:8b)

Respond in valid JSON only:
{{
  "sensitivity": float,
  "complexity": float,
  "route": "LOCAL"|"CLOUD",
  "reasoning": "one-line justification"
}}

Task: {task_input}
Task Type: {task_type}""",
    # Exploit Selection Prompt (CLAUDE.md §2.2)
    "exploit_selection": """You are a red team operator selecting Metasploit modules for authorized exploitation.  # noqa: E501

Service: {service_info}
CVE Candidates: {cve_candidates}
Prior Failures: {prior_failures}

Recommend up to 3 Metasploit modules. Output MUST be valid JSON:
{{
  "recommendations": [
    {{
      "module_path": "exploit/...",
      "options": {{}},
      "payload": "payload/...",
      "confidence": 0.0-1.0,
      "reasoning": "..."
    }}
  ]
}}

Only suggest modules that are likely to exist in Metasploit.""",
    # Verification Post-Mortem Prompt (CLAUDE.md §2.4)
    "verification_post_mortem": """You are an exploit verification specialist.

Analyze this exploitation result:

Exploit Result: {exploit_result}
Session Info: {session_info}

Generate structured post-mortem in JSON format.""",
    # Recon Analysis Prompt
    "recon_analysis": """You are a reconnaissance specialist. Analyze the Nmap/Gobuster output and extract structured information.""",  # noqa: E501
}


def get_prompt(template_name: str, **kwargs: Any) -> str:
    """Retrieve and format a prompt template."""
    if template_name not in PROMPTS:
        raise ValueError(f"Unknown prompt template: {template_name}")
    template = PROMPTS[template_name]
    return template.format(**kwargs) if kwargs else template


# Export common prompts
__all__ = ["PROMPTS", "get_prompt"]
