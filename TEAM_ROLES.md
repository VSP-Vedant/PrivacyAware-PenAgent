# TEAM_ROLES.md — Strict Accountability System

> **Non-negotiable ownership boundaries. Every file has ONE owner.**
> **Crossing boundaries without approval = PR rejected.**

---

## Member A — LLM/AI Lead

### Responsibilities (OWNS)

| Area | Files | Deliverables |
|------|-------|-------------|
| LLM Router | `src/router/llm_router.py` | Runtime routing logic |
| Sensitivity Classifier | `src/router/sensitivity.py` | Keyword/regex sensitivity scoring |
| Complexity Classifier | `src/router/complexity.py` | Task-type complexity mapping |
| Prompt Engineering | `src/config/prompts.py` | All agent prompt templates |
| LLM Benchmarking | `docs/llm_benchmarks.md` | Local vs cloud performance data |
| Cost Tracking | `src/router/cost_tracker.py` | Token + USD tracking per run |

### MUST NOT Touch

- `src/agents/orchestrator.py` (Member B)
- `src/tools/*` (Member C)
- `src/state/*` (Member D)
- `src/reporting/*` (Member D)
- CI/CD workflow files (Member B)

### Weekly Deliverables

| Week Range | Expected Output |
|------------|----------------|
| W1–6 | Ollama setup, 5-prompt benchmark, API keys tested |
| W7–12 | Sensitivity + complexity classifiers, router unit tests |
| W13–18 | Exploit selection prompts, cost tracking |
| W19–22 | Cloud call analysis, router threshold tuning |
| W23–28 | PentestGPT baseline reproduction, routing ablation data |
| W29–32 | LLM analysis paper section, final threshold calibration |

### KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Router accuracy | ≥85% correct routing on test suite | Manual review of 50 routing decisions |
| Cloud cost per target | ≤$0.50 average | Logged by cost tracker |
| Prompt test coverage | ≥90% of prompt templates tested | pytest count |
| Hallucination detection rate | ≥95% caught before execution | Hallucination log analysis |

### Failure Triggers

- Router misroutes sensitive data to cloud in production run → immediate fix required
- No benchmark data by Week 6 → pair with Member C for catch-up
- Cost tracking not functional by Week 18 → evaluation cannot proceed

---

## Member B — Backend/Orchestration Lead

### Responsibilities (OWNS)

| Area | Files | Deliverables |
|------|-------|-------------|
| Orchestrator | `src/agents/orchestrator.py` | LangGraph state machine |
| Main Entry Point | `src/main.py` | CLI interface, argument parsing |
| Agent Integration | LangGraph wiring | All agent nodes connected |
| CI/CD Pipelines | `.github/workflows/*` | All GitHub Actions |
| Ablation Flags | CLI flags in `main.py` | `--no-router`, `--no-graph`, `--no-verify` |
| Loop Control | Orchestrator logic | Termination, retry, replan edges |

### MUST NOT Touch

- `src/router/*` (Member A)
- `src/tools/*` (Member C)
- `src/state/attack_graph.py` (Member D)
- `src/reporting/*` (Member D)
- Prompt templates (Member A)

### Weekly Deliverables

| Week Range | Expected Output |
|------------|----------------|
| W1–6 | Repo setup, CI skeleton, LangGraph skeleton |
| W7–12 | Orchestrator with conditional edges, recon integration |
| W13–18 | Exploit + verify agent integration, retry loop |
| W19–22 | Full graph with termination, replan edge |
| W23–28 | Ablation flags, batch evaluation runner |
| W29–32 | Architecture paper section, repo cleanup |

### KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| CI pipeline uptime | 100% (no broken main/dev) | GitHub Actions history |
| Integration test pass rate | ≥90% | pytest results |
| Loop termination correctness | Zero infinite loops | Run logs |
| Ablation flag correctness | Each flag independently disables component | Manual verification |

### Failure Triggers

- CI broken on `dev` for >24h → must fix before any other work
- LangGraph skeleton not working by Week 6 → project timeline at risk
- Infinite loop in production run → immediate hotfix

---

## Member C (Vedant) — Security/Tools Lead & Repo Owner

### Responsibilities (OWNS)

| Area | Files | Deliverables |
|------|-------|-------------|
| Nmap Wrapper | `src/tools/nmap_wrapper.py` | XML parsing, service extraction |
| Gobuster Wrapper | `src/tools/gobuster_wrapper.py` | Subprocess + output parsing |
| Metasploit RPC | `src/tools/metasploit_rpc.py` | Module search, execute, sessions |
| SearchSploit | `src/tools/searchsploit.py` | Fallback exploit lookup |
| Recon Agent | `src/agents/recon_agent.py` | Full recon pipeline |
| Exploit Agent | `src/agents/exploit_agent.py` | Exploit execution pipeline |
| Evaluation Execution | `data/evaluation/` | Running all HTB evaluations |

### MUST NOT Touch

- `src/router/*` (Member A)
- `src/agents/orchestrator.py` (Member B)
- `src/state/*` (Member D)
- `src/reporting/*` (Member D)
- CI/CD files (Member B)

### Weekly Deliverables

| Week Range | Expected Output |
|------------|----------------|
| W1–6 | Tool wrappers tested, MSF RPC connected, HTB VPN working |
| W7–12 | Recon Agent complete, CVE mapping, Gobuster integration |
| W13–18 | Exploit Agent, module validation, searchsploit fallback |
| W19–22 | End-to-end testing on 5 machines |
| W23–28 | Full evaluation execution (120 runs) |
| W29–32 | Evaluation paper section |

### KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Tool wrapper reliability | Zero crashes on valid input | Integration tests |
| Nmap parse accuracy | 100% port/service extraction | Verified against raw XML |
| MSF RPC stability | Zero connection drops per run | Session logs |
| Evaluation completion | 120/120 runs executed | Data files |

### Failure Triggers

- Tool wrapper crashes on production scan → immediate fix
- Metasploit RPC connection unstable by Week 6 → escalate to team
- Evaluation runs incomplete by Week 28 → scope evaluation to minimum

---

## Member D — Data/State/Reporting Lead

### Responsibilities (OWNS)

| Area | Files | Deliverables |
|------|-------|-------------|
| Attack Graph | `src/state/attack_graph.py` | NetworkX graph operations |
| Persistence | `src/state/persistence.py` | SQLite serialization |
| Schemas | `src/state/schemas.py` | Node/edge type definitions |
| Verification Agent | `src/agents/verification_agent.py` | Session confirmation, post-mortem |
| Reporting | `src/reporting/report_generator.py` | HTML/MD report generation |
| Logging Config | `src/utils/logging_config.py` | Structured JSON logging |
| Data Analysis | `data/analysis/` | Metrics computation, charts |

### MUST NOT Touch

- `src/router/*` (Member A)
- `src/agents/orchestrator.py` (Member B)
- `src/tools/*` (Member C)
- `src/agents/recon_agent.py` (Member C)
- `src/agents/exploit_agent.py` (Member C)

### Weekly Deliverables

| Week Range | Expected Output |
|------------|----------------|
| W1–6 | Graph schema, SQLite layer, logging infrastructure |
| W7–12 | Graph with host/service nodes, persistence, queries |
| W13–18 | Verification agent, post-mortem generation, failure tracking |
| W19–22 | Report generator, metrics computation |
| W23–28 | Data analysis, comparison tables, charts |
| W29–32 | Related work + results paper sections |

### KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Graph persistence reliability | Zero data loss | Serialize→deserialize round-trip tests |
| Post-mortem generation rate | 100% of failures logged | Log analysis |
| Report completeness | All graph data reflected | Manual review |
| Metrics accuracy | Verified against raw logs | Cross-validation |

### Failure Triggers

- Data loss in attack graph → critical bug, immediate fix
- Logging not producing structured JSON by Week 6 → blocks all observability
- Reports missing data → blocks evaluation analysis

---

## Shared Responsibilities

| Task | Owners | Frequency |
|------|--------|-----------|
| Weekly standup | ALL | Weekly, fixed day |
| Code review (PRs) | ALL (rotate) | Per PR |
| Paper writing | ALL | Phase 6 |
| Ethical compliance | ALL | Continuous |
| `.env` management | ALL | Never commit |

---

## Cross-Boundary Protocol

When work requires touching another member's files:

1. Create issue describing the change needed
2. Assign to file owner
3. File owner implements OR grants explicit written approval (GitHub comment)
4. Approved cross-boundary work must include the owner as PR reviewer
5. Owner has final merge authority on their files

**Violation:** PR modifying files outside ownership without approval → auto-rejected by reviewer.

---

## Replacement Protocol

If a member consistently underperforms (3+ missed deliverables):

1. **Week 1:** Documented in standup. Pair programming assigned with strongest member.
2. **Week 2:** Responsibilities redistributed temporarily. Member gets catch-up sprint.
3. **Week 3:** If no improvement, escalate to supervisor. Permanent redistribution discussed.
4. **Supervisor decision:** Member may be reassigned to documentation-only role. Core development reassigned.

No member is removed from the team. Responsibilities shift to maintain project velocity.

---

*Ownership is absolute. Ambiguity in ownership is a bug — resolve immediately in standup.*
