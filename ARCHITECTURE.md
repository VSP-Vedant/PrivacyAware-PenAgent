# ARCHITECTURE.md — System Architecture

> **PrivacyAware-PenAgent** — Complete architectural specification
> **Status:** Canonical reference — all implementation must conform

---

## 1. System Overview

Seven interconnected modules. All agent-to-agent communication flows through LangGraph's state machine. All tool invocations via Python subprocess wrappers or native APIs.

```
┌────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR LAYER                       │
│          LangGraph State Graph (main.py entry point)        │
│  Controls agent sequencing, conditional routing, termination │
└───────────────────┬────────────────────────────────────────┘
                    │
       ┌────────────┴────────────┐
       │                         │
┌──────▼──────┐         ┌───────▼───────┐
│  RECON       │         │  EXPLOIT       │
│  AGENT       │         │  AGENT         │
│  (Nmap +     │         │  (Metasploit   │
│  Gobuster)   │         │  RPC +         │
│              │         │  SearchSploit) │
└──────┬───────┘         └───────┬───────┘
       │                         │
       └────────────┬────────────┘
                    │
          ┌─────────▼──────────┐
          │  ATTACK GRAPH       │
          │  STATE MANAGER      │
          │  (NetworkX + SQLite)│
          └─────────┬───────────┘
                    │
          ┌─────────▼──────────┐
          │  LLM ROUTER         │
          │  (Sensitivity +     │
          │  Complexity scorer)  │
          └────────┬────────────┘
                   │
       ┌───────────┴──────────┐
       │                      │
┌──────▼──────┐      ┌───────▼──────┐
│  LOCAL LLM   │      │  CLOUD LLM   │
│  Ollama:     │      │  GPT-4o /    │
│  Llama3 8B   │      │  Claude      │
└──────────────┘      └──────────────┘
                    │
          ┌─────────▼──────────┐
          │  VERIFICATION &     │
          │  REPORTING AGENT    │
          └─────────────────────┘
```

---

## 2. Component Deep Dive

### 2.1 Orchestrator (LangGraph)

**Owner:** Vighnesh (Member B)
**File:** `src/agents/orchestrator.py`

The Orchestrator is the root LangGraph `StateGraph`. It defines:

- **Nodes:** `recon`, `analyze`, `exploit`, `verify`, `report`, `replan`
- **Edges:** Conditional routing based on attack graph state
- **Termination:** Flag captured OR step budget exceeded OR no remaining exploit paths
- **State:** Shared `TypedDict` passed between all nodes

```python
class PenTestState(TypedDict):
    target: str
    attack_graph: AttackGraph
    current_phase: Literal["recon", "exploit", "verify", "report", "done"]
    exploit_attempts: list[ExploitAttempt]
    sessions: list[SessionInfo]
    step_count: int
    max_steps: int
    cloud_tokens_used: int
    findings: list[Finding]
```

**Decision Logic:**

```
START → recon → analyze_graph
                    │
            ┌───────┴───────┐
            │               │
     has_exploitable   no_targets
            │               │
         exploit          report
            │
         verify
            │
     ┌──────┴──────┐
     │             │
   success      failure
     │             │
   report       replan ──→ exploit (max 3 retries)
```

**Loop Prevention:**
- Hard step budget (`MAX_TOTAL_STEPS=100`)
- Per-service exploit retry cap (`MAX_EXPLOIT_RETRIES=3`)
- Negative edge tracking — never retry same module+payload on same service
- Timeout per LangGraph run (configurable, default 30 minutes)

---

### 2.2 Recon Agent

**Owner:** Vedant (Member C)
**File:** `src/agents/recon_agent.py`
**Dependencies:** `src/tools/nmap_wrapper.py`, `src/tools/gobuster_wrapper.py`

**Responsibilities:**
1. Execute Nmap scan (`-sV -sC -O -oX`) against target
2. Parse XML output → structured service dictionaries
3. If HTTP/HTTPS ports found → trigger Gobuster
4. Map discovered service versions → CVE candidates (via `python-nvdlib` or ExploitDB CSV)
5. Write all discoveries as nodes/edges to attack graph

**Output Schema:**

```python
@dataclass
class ReconResult:
    hosts: list[HostInfo]
    services: list[ServiceInfo]
    web_endpoints: list[WebEndpoint]
    cve_candidates: list[CVECandidate]
    os_guess: str | None
    scan_duration_seconds: float
```

**Nmap Integration:**
- Library: `python-nmap` (XML parsing)
- Scan types: TCP SYN (`-sS`), service version (`-sV`), OS detection (`-O`), default scripts (`-sC`)
- Output: XML (`-oX`) parsed into `ServiceInfo` dicts with `port`, `protocol`, `service`, `version`, `state`

**Gobuster Integration:**
- Invoked via `subprocess` when HTTP(S) ports detected
- Wordlist: `/usr/share/wordlists/dirb/common.txt`
- Output parsed line-by-line, status-code filtered (200, 301, 302, 403)
- Stored as `WebEndpoint` nodes in attack graph

---

### 2.3 Exploit Agent

**Owner:** Vedant (Member C, tool wrappers), Prajyot (Member A, LLM prompting)
**File:** `src/agents/exploit_agent.py`
**Dependencies:** `src/tools/metasploit_rpc.py`, `src/tools/searchsploit.py`

**Responsibilities:**
1. Receive candidate exploit paths from attack graph
2. Query LLM (via Router) for Metasploit module recommendation
3. Validate module exists via `modules.search`
4. Execute exploit via Metasploit RPC
5. Write result (success/failure) to attack graph

**Metasploit RPC Flow:**

```
1. modules.search(service_version) → candidate_modules[]
2. LLM selects best module + options + payload
3. Validate: module exists in search results?
   YES → module.execute(module, options, payload)
   NO  → Log hallucination, try searchsploit fallback
4. Check sessions.list → session opened?
   YES → Write success edge to graph
   NO  → Write failure edge with error, trigger replan
```

**Hallucination Mitigation:**
- ALL LLM-suggested module names validated against `modules.search` response
- Non-existent modules logged as `hallucination_event`
- Hallucination rate tracked as secondary metric
- Fallback chain: Metasploit search → SearchSploit → manual CVE lookup

---

### 2.4 LLM Router

**Owner:** Prajyot (Member A)
**File:** `src/router/llm_router.py`
**Dependencies:** `src/router/sensitivity.py`, `src/router/complexity.py`

**Core Innovation:** Runtime routing between local and cloud LLMs.

**Decision Logic:**

```python
def route(task_input: str, task_type: TaskType) -> RoutingDecision:
    sensitivity = classify_sensitivity(task_input)
    complexity = classify_complexity(task_type)

    if sensitivity > SENSITIVITY_THRESHOLD or complexity > COMPLEXITY_THRESHOLD:
        return RoutingDecision(model="gpt-4o", route="CLOUD")
    else:
        return RoutingDecision(model="llama3:8b", route="LOCAL")
```

**Sensitivity Classifier** (`src/router/sensitivity.py`):
- Regex/keyword scan for: raw IPs, credential patterns, session tokens, file paths, service banners
- Scoring: each pattern match adds weight; normalized to 0.0–1.0
- Conservative: if in doubt, score HIGH (privacy-first)

**Complexity Classifier** (`src/router/complexity.py`):
- Task-type enum maps to base complexity:
  - `SUMMARIZE` → 0.1
  - `FORMAT_OUTPUT` → 0.2
  - `COMMAND_TEMPLATE` → 0.3
  - `CVE_LOOKUP` → 0.5
  - `EXPLOIT_SELECTION` → 0.7
  - `PRIV_ESC_REASONING` → 0.9
  - `MULTI_CVE_CHAIN` → 1.0

**Cost Tracking:**
- Every routing decision logged with model, tokens, latency, cost
- Per-run cloud token budget enforced (`MAX_CLOUD_TOKENS_PER_RUN`)
- Budget exceeded → force local routing with degradation warning

---

### 2.5 Attack Graph Manager

**Owner:** Parth (Member D)
**File:** `src/state/attack_graph.py`
**Dependencies:** `src/state/persistence.py`, `src/state/schemas.py`

**Data Model:** Directed graph (NetworkX `DiGraph`)

**Node Types:**

| Type | Attributes |
|------|-----------|
| `host` | `ip`, `hostname`, `os_guess`, `status` |
| `service` | `port`, `protocol`, `name`, `version`, `state` |
| `web_endpoint` | `url`, `status_code`, `content_type` |
| `cve` | `cve_id`, `cvss_score`, `description`, `exploitdb_ref` |
| `session` | `session_id`, `privilege`, `shell_type` |

**Edge Types:**

| Type | From → To | Attributes |
|------|-----------|-----------|
| `hosts_service` | host → service | — |
| `has_endpoint` | service → web_endpoint | — |
| `vulnerable_to` | service → cve | `confidence` |
| `exploit_attempt` | cve → session/failure | `module`, `result`, `timestamp`, `post_mortem` |
| `escalated_to` | session → session | `method`, `from_priv`, `to_priv` |

**Persistence (SQLite):**
- Serialize: `nx.node_link_data(graph)` → JSON → SQLite
- Deserialize: SQLite → JSON → `nx.node_link_graph(data)`
- Auto-save after every graph mutation
- Session-based: `runs/<target>_<timestamp>.db`

**Query Interface:**

```python
def get_exploitable_services(self) -> list[ServiceNode]
def get_failed_exploits(self, service_id: str) -> list[ExploitAttempt]
def get_cve_candidates(self, service_id: str) -> list[CVENode]
def has_active_session(self) -> bool
def get_privilege_level(self) -> str  # "none" | "user" | "root"
```

---

### 2.6 Verification Agent

**Owner:** Parth (Member D, implementation), Vighnesh (Member B, integration)
**File:** `src/agents/verification_agent.py`

**Responsibilities:**
1. After exploit attempt: check `sessions.list` via Metasploit RPC
2. If session exists: run `id` command to confirm privilege level
3. On success: log to attack graph, check if root → trigger report or escalation
4. On failure: generate structured JSON post-mortem

**Post-Mortem Schema:**

```python
@dataclass
class ExploitPostMortem:
    target_service: str
    module_used: str
    error_type: Literal["no_session", "timeout", "connection_refused", "auth_failed", "module_not_found"]
    raw_error: str
    hypothesis: str  # LLM-generated root cause
    recommended_action: Literal["retry_different_payload", "try_alternative_module", "skip_service", "manual_review"]
    timestamp: str
```

**Feedback Loop:**
- Post-mortem written as negative edge in attack graph
- Orchestrator reads failure context before next exploit attempt
- Failed module+payload combinations blacklisted for that service
- Max 3 retries per service before marking as `skip_service`

---

### 2.7 Reporting Agent

**Owner:** Parth (Member D)
**File:** `src/reporting/report_generator.py`

Generates structured report from attack graph:
- Network topology diagram (from graph nodes)
- Services table (port, service, version, CVEs)
- Exploit timeline (ordered attempts with outcomes)
- Findings (successful exploits with evidence)
- Metrics summary (SR, steps, cloud calls, cost)

**Output Formats:** HTML (primary), Markdown (secondary)

---

## 3. Data Flow

```
1. Input: target IP → Orchestrator initializes empty attack graph
2. Recon Agent: Nmap → Gobuster → writes services to graph
3. Orchestrator: queries graph → exploitable services? → YES → Exploit Agent
4. Exploit Agent: queries Router → selects model → LLM suggests modules
5. Exploit Agent: validates module → executes via MSF RPC → writes result
6. Verification: checks session → confirms privilege → success/failure
7. On failure: post-mortem → graph → Orchestrator → replan → Exploit Agent
8. On success: root? → report | user? → priv esc attempt
9. Report: reads full graph → generates HTML/MD report
```

---

## 4. Design Trade-offs

| Decision | Alternative | Rationale |
|----------|-------------|-----------|
| NetworkX (in-memory) | Neo4j | Zero infrastructure cost; sufficient for single-host targets; SQLite backup handles persistence |
| LangGraph over LangChain AgentExecutor | AgentExecutor | LangGraph provides explicit state machine with conditional edges; AgentExecutor is less controllable for multi-agent loops |
| Regex sensitivity classifier | ML classifier | Faster, deterministic, auditable; ML classifier adds training complexity for marginal gain on known pattern types |
| SQLite over PostgreSQL | PostgreSQL | Stdlib, zero setup, file-based; 4-person project doesn't need concurrent DB access |
| Ollama over llama.cpp | llama.cpp | Ollama provides REST API, model management, easier GPU config; llama.cpp is faster but harder to integrate |
| pymetasploit3 over subprocess | Direct msfconsole subprocess | Structured RPC is reliable; subprocess parsing of msfconsole is fragile |
| Threshold-based routing | ML-based routing | Interpretable, tunable, auditable; ML routing requires labeled training data we don't have |

---

*This document is the architectural source of truth. All implementation must conform to these specifications.*
