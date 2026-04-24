# CLAUDE.md — AI System Governor

> **Project:** PrivacyAware-PenAgent
> **Scope:** All AI-assisted development, code generation, and agent prompt engineering
> **Enforcement:** MANDATORY for every contributor and every AI session
> **Last Updated:** April 2026

---

## 1. SYSTEM RULES

### 1.1 AI-Assisted Development Protocol

Every AI-generated code artifact MUST:

1. Be reviewed by the assigned module owner before merge
2. Include inline comments explaining non-obvious logic
3. Pass all CI checks (lint, type, test, security scan) before PR creation
4. Never introduce dependencies not listed in `requirements.txt`
5. Never hardcode credentials, API keys, IP addresses, or file paths

### 1.2 Session Rules

- Start every AI session with: `"You are working on PrivacyAware-PenAgent. Current phase: [N]. My role: [A/B/C/D]. Module: [name]."`
- Never ask AI to generate code for modules outside your ownership boundary (see TEAM_ROLES.md)
- All AI-generated code must be committed with prefix `ai:` in commit message (e.g., `ai: implement nmap parser`)
- AI sessions generating >200 lines must be split into logical commits

### 1.3 Prohibited AI Actions

The following are NEVER permitted regardless of context:

- Generating code that connects to non-authorized targets (anything outside HTB VPN, local VMs, or localhost)
- Generating exploit payloads targeting real-world systems
- Storing credentials in source code, comments, or logs
- Disabling security checks, linting, or test requirements
- Generating code that exfiltrates data outside the lab environment
- Using AI to bypass code review or CI requirements

---

## 2. PROMPT STANDARDS

### 2.1 Recon Agent Prompts

```
SYSTEM: You are a reconnaissance specialist operating within an authorized penetration test.
Your task is to analyze scan output and identify exploitable services.

CONSTRAINTS:
- Only suggest actions against the provided target IP/hostname
- Output MUST be structured JSON with keys: services[], os_guess, web_endpoints[], cve_candidates[]
- Never suggest scanning networks beyond the target scope
- Flag any service version that maps to a known CVE with CVSS >= 7.0

INPUT: {nmap_xml_output}
OUTPUT FORMAT: {structured_json_schema}
```

### 2.2 Exploit Agent Prompts

```
SYSTEM: You are a red team operator selecting Metasploit modules for authorized exploitation.
You receive a service description and CVE candidates. You recommend exploit modules.

CONSTRAINTS:
- ONLY suggest modules that exist in Metasploit Framework (will be validated via modules.search)
- Output MUST include: module_path, required_options{}, recommended_payload, confidence_score (0-1)
- If no matching module exists, respond with: {"fallback": "searchsploit", "query": "<service-version>"}
- Never suggest modules for services not in the provided attack graph state
- Maximum 3 module suggestions per service, ranked by confidence

INPUT: {service_info, cve_candidates, prior_failures[]}
OUTPUT FORMAT: {exploit_recommendation_schema}
```

### 2.3 LLM Router Classification Prompts

```
SYSTEM: You are a task classifier for a hybrid LLM routing system.
Classify the following task on two dimensions:

1. DATA_SENSITIVITY (0.0-1.0): Does the input/output contain credentials, IPs, session tokens, file paths from target systems?
2. REASONING_COMPLEXITY (0.0-1.0): Does this task require multi-hop inference, CVE chaining, or privilege escalation reasoning?

ROUTING RULES:
- sensitivity > 0.6 OR complexity > 0.7 → CLOUD
- Otherwise → LOCAL

OUTPUT: {"sensitivity": float, "complexity": float, "route": "LOCAL"|"CLOUD", "reasoning": "one-line justification"}
```

### 2.4 Verification Agent Prompts

```
SYSTEM: You are an exploit verification specialist. Analyze the following exploitation result.

TASKS:
1. Determine if exploitation succeeded (shell obtained, flag captured, privilege confirmed)
2. If failed: generate a structured post-mortem with failure_type, root_cause_hypothesis, and recommended_next_action
3. If succeeded: confirm privilege level and recommend post-exploitation steps

INPUT: {exploit_result, session_info, attack_graph_state}
OUTPUT FORMAT: {verification_result_schema}
```

---

## 3. CODING CONSTRAINTS

### 3.1 Language and Style

| Rule | Enforcement |
|------|-------------|
| Python 3.10+ only | CI rejects older syntax |
| Type hints on ALL function signatures | `mypy --strict` in CI |
| Docstrings on ALL public functions (Google style) | `pydocstyle` check |
| Max line length: 88 characters | `black` formatter |
| Import sorting: `isort` profile black | CI enforced |
| No `print()` statements | Use `logging` module exclusively |
| No `except:` bare exceptions | Must catch specific exception types |
| No mutable default arguments | Use `None` + conditional assignment |
| F-strings only (no `.format()` or `%`) | Linter enforced |

### 3.2 Project Structure Enforcement

```
src/
├── agents/
│   ├── __init__.py
│   ├── recon_agent.py          # Vedant owns
│   ├── exploit_agent.py        # Vedant owns
│   ├── verification_agent.py   # Parth owns
│   └── orchestrator.py         # Vighnesh owns
├── router/
│   ├── __init__.py
│   ├── llm_router.py           # Prajyot owns
│   ├── sensitivity.py          # Prajyot owns
│   └── complexity.py           # Prajyot owns
├── state/
│   ├── __init__.py
│   ├── attack_graph.py         # Parth owns
│   ├── persistence.py          # Parth owns
│   └── schemas.py              # Parth owns
├── tools/
│   ├── __init__.py
│   ├── nmap_wrapper.py         # Vedant owns
│   ├── gobuster_wrapper.py     # Vedant owns
│   ├── metasploit_rpc.py       # Vedant owns
│   └── searchsploit.py         # Vedant owns
├── reporting/
│   ├── __init__.py
│   ├── report_generator.py     # Parth owns
│   └── templates/
├── config/
│   ├── __init__.py
│   ├── settings.py
│   └── prompts.py              # Prajyot owns
├── utils/
│   ├── __init__.py
│   ├── logging_config.py       # Parth owns
│   └── validators.py
└── main.py                     # Vighnesh owns
tests/
├── unit/
├── integration/
└── conftest.py
```

### 3.3 Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Files | `snake_case.py` | `recon_agent.py` |
| Classes | `PascalCase` | `ReconAgent` |
| Functions | `snake_case` | `parse_nmap_output()` |
| Constants | `UPPER_SNAKE` | `MAX_EXPLOIT_RETRIES` |
| Private methods | `_leading_underscore` | `_validate_module()` |
| Test files | `test_<module>.py` | `test_recon_agent.py` |
| Test functions | `test_<behavior>` | `test_parses_open_ports()` |

---

## 4. SECURITY AND ETHICAL BOUNDARIES

### 4.1 Hard Boundaries (VIOLATION = IMMEDIATE PROJECT REMOVAL)

1. **Target Scope**: ONLY HackTheBox (via VPN), local Metasploitable VMs, personal lab VMs, or localhost
2. **No Real Targets**: Never point tools at production systems, university networks, or any unauthorized target
3. **Credential Handling**: All credentials stored in `.env` files, NEVER committed. `.env` is in `.gitignore`
4. **Data Retention**: Scan results from HTB machines may be stored locally. NEVER upload raw scan data to public repos
5. **API Key Protection**: OpenAI/Anthropic keys loaded from environment variables only
6. **Ethical Declaration**: Signed ethical use declaration must be on file with supervisor before Phase 2

### 4.2 Runtime Safety

```python
# MANDATORY: Every tool wrapper must enforce target validation
ALLOWED_TARGET_RANGES = [
    "10.10.0.0/16",      # HackTheBox VPN range
    "10.129.0.0/16",     # HackTheBox VPN range (alternate)
    "192.168.56.0/24",   # Local VirtualBox host-only
    "172.17.0.0/16",     # Docker containers
    "127.0.0.1",         # Localhost
]

def validate_target(ip: str) -> bool:
    """Reject any target not in allowed ranges. No exceptions."""
    return any(ip_address(ip) in ip_network(net) for net in ALLOWED_TARGET_RANGES)
```

---

## 5. LOGGING AND OBSERVABILITY

### 5.1 Logging Standards

Every module MUST use the centralized logging configuration:

```python
import logging
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)
```

### 5.2 Required Log Events

| Event | Level | Required Fields |
|-------|-------|----------------|
| Agent invocation | `INFO` | `agent_name`, `target`, `timestamp` |
| Tool execution | `INFO` | `tool_name`, `command`, `target`, `duration_ms` |
| LLM routing decision | `INFO` | `task_type`, `sensitivity_score`, `complexity_score`, `route`, `model` |
| LLM API call | `DEBUG` | `model`, `prompt_tokens`, `completion_tokens`, `latency_ms`, `cost_usd` |
| Exploit attempt | `WARNING` | `module`, `target_service`, `result`, `session_id` or `error` |
| Exploit success | `CRITICAL` | `module`, `target`, `session_id`, `privilege_level` |
| Exploit failure | `WARNING` | `module`, `target`, `error_type`, `post_mortem` |
| Attack graph mutation | `INFO` | `operation` (add_node/add_edge/update), `node_id`, `attributes` |
| Validation error | `ERROR` | `validator`, `input`, `reason` |
| Security boundary violation | `CRITICAL` | `action`, `target`, `blocked_reason` |

### 5.3 Log Format

```python
LOG_FORMAT = {
    "timestamp": "%(asctime)s",
    "level": "%(levelname)s",
    "module": "%(name)s",
    "function": "%(funcName)s",
    "message": "%(message)s",
    "extra": {}  # Structured JSON payload
}
```

All logs written to:
- `logs/penagent_<date>.jsonl` (structured JSON lines)
- Console output (human-readable format, `INFO` and above)

---

## 6. DEFINITION OF DONE (DoD)

A task is DONE when ALL of the following are true:

### Code
- [ ] Code compiles and runs without errors
- [ ] All new functions have type hints and docstrings
- [ ] `black` formatting applied
- [ ] `flake8` passes with zero warnings
- [ ] `mypy` passes with zero errors
- [ ] No `TODO` or `FIXME` comments left unresolved

### Testing
- [ ] Unit tests written (minimum 3 per public function)
- [ ] All tests pass locally
- [ ] Coverage for changed files ≥ 70%
- [ ] Integration test added if module interfaces changed

### Review
- [ ] PR created with description template filled
- [ ] At least 1 reviewer approved (not the author)
- [ ] CI pipeline passes all checks
- [ ] No merge conflicts with `dev` branch

### Documentation
- [ ] README updated if public interface changed
- [ ] Docstrings updated for modified functions
- [ ] CHANGELOG entry added for user-facing changes

---

## 7. INVALID WORK CONDITIONS (REJECT CRITERIA)

A PR or task submission is AUTOMATICALLY REJECTED if any of the following apply:

| Condition | Reason |
|-----------|--------|
| Code targets unauthorized systems | Ethical violation — escalate to supervisor |
| Credentials in source code | Security violation |
| No tests for new functionality | DoD violation |
| `print()` used instead of `logging` | Coding standard violation |
| Module modified outside ownership boundary | Role violation (see TEAM_ROLES.md) |
| CI pipeline not passing | Quality gate failure |
| PR description template not filled | Process violation |
| AI-generated code without `ai:` commit prefix | Traceability violation |
| Bare `except:` clauses | Error handling violation |
| No type hints on function signatures | Type safety violation |
| Coverage drops below 70% | Testing threshold violation |
| Dependencies added without team approval | Dependency management violation |

### Rejection Flow

1. Reviewer marks PR as "Changes Requested" with specific rejection reason
2. Author has 48 hours to fix and re-request review
3. If not fixed in 48 hours, task moves back to "Backlog" and is flagged in weekly standup
4. Third rejection of same PR → escalate to team lead for pair programming session

---

## 8. VERSION CONTROL RULES

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `ai`

Examples:
```
feat(recon): add nmap XML parser with CVE lookup
ai(router): implement sensitivity classifier
fix(exploit): handle metasploit session timeout
test(graph): add persistence serialization tests
```

### Branch Naming

```
feature/<issue-number>-<short-description>
bugfix/<issue-number>-<short-description>
hotfix/<issue-number>-<short-description>
```

---

*This document is the supreme authority for all development activity. Violations are tracked and reported in weekly standups.*
