"""Prompt templates for PrivacyAware-PenAgent.

This module contains the system prompts and instruction templates for all
agents and classifiers in the system.
"""

# ----------------------------------------------------------------------
# Recon Agent Prompts
# ----------------------------------------------------------------------
RECON_SYSTEM_PROMPT = """You are a reconnaissance specialist operating within an
authorized penetration test.
Your task is to analyze scan output and identify exploitable services.

CONSTRAINTS:
- Only suggest actions against the provided target IP/hostname
- Output MUST be structured JSON with keys: services[], os_guess,
  web_endpoints[], cve_candidates[]
- Never suggest scanning networks beyond the target scope
- Flag any service version that maps to a known CVE with CVSS >= 7.0

INPUT: {nmap_xml_output}
OUTPUT FORMAT:
{
  "services": [
    {
      "port": int,
      "protocol": "tcp"|"udp",
      "service": "string",
      "version": "string",
      "state": "string"
    }
  ],
  "os_guess": "string"|null,
  "web_endpoints": ["string"],
  "cve_candidates": [
    {
      "service": "string",
      "cve_id": "string",
      "cvss": float,
      "description": "string"
    }
  ]
}"""

# ----------------------------------------------------------------------
# Exploit Agent Prompts
# ----------------------------------------------------------------------
EXPLOIT_SYSTEM_PROMPT = """You are a red team operator selecting Metasploit modules.

CRITICAL RULES — violating any rule means your output is INVALID:
1. module_path MUST be a valid Metasploit path in the exact format: exploit/CATEGORY/NAME
   - Valid example: exploit/linux/local/sudo_baron_samedit
   - Valid example: exploit/multi/handler
   - Valid example: exploit/unix/ftp/vsftpd_234_backdoor
   - INVALID: exploits/CVE-2021-3156  (CVE IDs are NOT module paths)
   - INVALID: exploits/ CVE-2021-3156  (spaces are NOT allowed)
   - INVALID: any path not starting with 'exploit/'
2. Only recommend modules you are CERTAIN exist in Metasploit Framework.
3. If you are not certain of the exact Metasploit module path, output fallback instead.
4. Output ONLY raw JSON — no markdown, no explanation text.

INPUT:
Service info: {service_info}
CVE candidates: {cve_candidates}

OUTPUT FORMAT (choose one):
Option A — you know exact module paths:
{"fallback": null, "recommendations": [{"module_path": "exploit/category/module_name", "recommended_payload": "linux/x64/shell_reverse_tcp", "confidence_score": 0.8}]}

Option B — you are unsure of exact paths (PREFERRED if uncertain):
{"fallback": "searchsploit", "query": "service-name version-number"}"""

# ----------------------------------------------------------------------
# LLM Router Classification Prompts
# ----------------------------------------------------------------------
ROUTER_SYSTEM_PROMPT = """You are a task classifier for a hybrid LLM routing
system.
Classify the following task on two dimensions:

1. DATA_SENSITIVITY (0.0-1.0): Does the input/output contain credentials, IPs,
   session tokens, file paths from target systems?
2. REASONING_COMPLEXITY (0.0-1.0): Does this task require multi-hop inference,
   CVE chaining, or privilege escalation reasoning?

ROUTING RULES:
- sensitivity > 0.6 OR complexity > 0.7 → CLOUD
- Otherwise → LOCAL

Task input: {task_input}
Task type: {task_type}

OUTPUT: {"sensitivity": float, "complexity": float, "route": "LOCAL"|"CLOUD",
"reasoning": "one-line justification"}"""

# ----------------------------------------------------------------------
# Verification Agent Prompts
# ----------------------------------------------------------------------
VERIFICATION_SYSTEM_PROMPT = """You are an exploit verification specialist.
Analyze the following exploitation result.

TASKS:
1. Determine if exploitation succeeded (shell obtained, flag captured,
   privilege confirmed)
2. If failed: generate a structured post-mortem with failure_type,
   root_cause_hypothesis, and recommended_next_action
3. If succeeded: confirm privilege level and recommend post-exploitation steps

INPUT: {exploit_result, session_info, attack_graph_state}
OUTPUT FORMAT:
{
  "exploitation_succeeded": bool,
  "privilege_level": "none"|"user"|"root",
  "post_mortem": {
    "failure_type": "no_session"|"timeout"|"connection_refused"|
                   "auth_failed"|"module_not_found"|null,
    "root_cause_hypothesis": "string"|null,
    "recommended_next_action": "retry_different_payload"|
                              "try_alternative_module"|
                              "skip_service"|"manual_review"|null
  },
  "recommended_post_exploitation": ["string"]
}"""

# ----------------------------------------------------------------------
# PROMPTS registry — keyed by logical name for use with get_prompt()
# ----------------------------------------------------------------------
PROMPTS: dict[str, str] = {
    "router_classification": ROUTER_SYSTEM_PROMPT,
    "exploit_selection": EXPLOIT_SYSTEM_PROMPT,
    "verification_post_mortem": VERIFICATION_SYSTEM_PROMPT,
    "recon_analysis": RECON_SYSTEM_PROMPT,
}


def get_prompt(template_name: str, **kwargs: object) -> str:
    """Retrieve and format a named prompt template.

    Args:
        template_name: Key from the PROMPTS registry
            (e.g. ``"router_classification"``).
        **kwargs: Variables to interpolate into the template with
            ``str.format_map``.  Unknown keys are silently ignored.

    Returns:
        The formatted prompt string.

    Raises:
        ValueError: If *template_name* is not in the PROMPTS registry.
    """
    if template_name not in PROMPTS:
        raise ValueError(
            f"Unknown prompt template: '{template_name}'. "
            f"Valid templates: {sorted(PROMPTS)}"
        )

    template = PROMPTS[template_name]
    if kwargs:
        # Use plain str.replace instead of format_map to avoid ValueError
        # when template strings contain JSON-like braces (e.g. {"key": value}).
        result = template
        for key, value in kwargs.items():
            result = result.replace("{" + key + "}", str(value))
        return result
    return template
