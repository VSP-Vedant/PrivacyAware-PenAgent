# IMPLEMENTATION_PLAN.md — Enforced Timeline

> **32-week execution plan. No negotiation on deadlines.**
> **If missed → consequence applied. No exceptions.**

---

## MVP Definition (Must be complete by Week 12)

The MVP is a system that can:
1. Accept a target IP
2. Run automated Nmap reconnaissance
3. Populate an attack graph with discovered services
4. Route LLM calls between local and cloud based on sensitivity/complexity
5. Suggest (but not necessarily execute) exploit modules

If MVP is not demonstrated by Week 12, the project scope reduces to the semi-autonomous (assisted-agent) architecture. Router + graph contributions remain valid.

---

## Phase 1 — Research, Design & Environment Setup (Weeks 1–6)

### Week 1–2: Foundation

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Kali VM fully configured (Nmap, Gobuster, Metasploit installed) | C | Tools run without errors |
| Python 3.10+ venv with base dependencies | B | `pip install -r requirements.txt` succeeds |
| GitHub repo with branch strategy, CI skeleton, README | B | CI runs on push (even if empty) |
| Ollama installed + Llama3 8B + Mistral 7B pulled | A | `ollama run llama3` responds |
| Literature review draft (10 papers summarized) | ALL | 2-page doc in `docs/` |

**If missed:** Week 3 becomes catch-up. No Phase 2 work begins until all Week 1–2 items green.

### Week 3–4: Architecture Lock

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| ARCHITECTURE.md finalized with team consensus | ALL | Signed off in standup |
| Attack graph schema designed (node types, edge types) | D | Schema doc in `docs/` reviewed by B |
| LLM Router threshold values researched | A | 5 sample prompts tested local vs cloud |
| Metasploit RPC connection tested | C | `pymetasploit3` connects + lists modules |
| HackTheBox VPN configured + 1 easy machine solved manually | C | Flag submitted |

**If missed:** Architecture MUST lock by end of Week 5. Week 6 is buffer.
**HARD RULE:** No architecture changes after Week 6 without supervisor approval + unanimous team vote.

### Week 5–6: Skeleton + Toolchain

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| LangGraph skeleton: 3 nodes + 1 conditional edge | B | Graph compiles and runs with mock agents |
| Nmap XML parser → dict function | C | Unit tests pass on sample XML |
| Gobuster subprocess wrapper | C | Returns structured output on test target |
| SQLite persistence layer skeleton | D | Serialize/deserialize empty graph works |
| Logging infrastructure (JSON structured logs) | D | Log file generated on test run |
| Cloud API keys tested (OpenAI + Anthropic) | A | API call returns response |

**Checkpoint:** Phase 1 Review — ALL deliverables demonstrated in 30-min team meeting.

---

## Phase 2 — Core Agent Development (Weeks 7–12)

### Week 7–8: Recon Agent

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Recon Agent: full Nmap pipeline writing to attack graph | C | Scan of Metasploitable VM populates graph |
| Nmap output → CVE mapping (python-nvdlib or ExploitDB) | C | 3 services mapped to CVEs correctly |
| Attack graph: host + service nodes with attributes | D | Query `get_exploitable_services()` returns data |
| Attack graph: SQLite persistence working | D | Graph survives Python process restart |

### Week 9–10: LLM Router

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Sensitivity classifier (keyword/regex) | A | 10 test inputs scored correctly |
| Complexity classifier (task-type enum) | A | All task types map to expected scores |
| Router: routes to Ollama or cloud based on scores | A | Unit tests with mock LLM calls pass |
| Orchestrator: Recon → AttackGraph → conditional edge | B | `should_exploit` edge works on mock data |

### Week 11–12: Integration + MVP

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Recon + Graph + Router integrated in LangGraph | B | End-to-end recon run on HTB easy machine |
| Gobuster triggered on HTTP port detection | C | Web endpoints added to graph |
| Graph visualization (networkx → matplotlib/graphviz) | D | Graph rendered for debug inspection |
| **MVP DEMO** | ALL | Target → Recon → Graph → Router → LLM suggestion |

**Checkpoint:** MVP Demo — presented to supervisor. If not achieved, fallback to assisted-agent architecture.

**If MVP missed:** 
- Scope reduces to assisted-agent mode
- Remove autonomous exploit execution from scope
- Router + graph remain as thesis contribution
- Phase 3 timeline compresses by 2 weeks

---

## Phase 3 — Exploitation Agent & LLM Decision Layer (Weeks 13–18)

### Week 13–14: Exploit Agent Core

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Metasploit RPC: `module_execute()` wrapper | C | Exploit runs against Metasploitable VM |
| LLM exploit selection prompt + structured output | A | LLM returns valid module recommendations |
| Module validation (check against `modules.search`) | C | Hallucinated module names caught + logged |
| SearchSploit fallback when no MSF module found | C | Fallback triggers correctly |

### Week 15–16: Verification Agent

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Session confirmation via `sessions.list` | C | Session detected after successful exploit |
| Privilege check (`id` command via session) | D | Returns "root" or "user" correctly |
| Structured JSON post-mortem on failure | D | Post-mortem generated with hypothesis |
| Failure post-mortem → attack graph negative edge | D | Graph tracks failed attempts |

### Week 17–18: End-to-End

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Full pipeline: target → recon → exploit → verify | B | 1 HTB easy machine pwned autonomously |
| Retry loop (max 3 per exploit path) | B | Retries with different modules on failure |
| Replan edge: verify failure → exploit with context | B | Replanning works with post-mortem input |
| Cost tracking: tokens + USD per run | A | Cost logged after each run |

**Checkpoint:** End-to-end demo — 1 machine pwned without human input.

**If missed:**
- Week 19 becomes debugging sprint
- Phase 4 compressed to 3 weeks
- Evaluation reduces to 6 targets instead of 10

---

## Phase 4 — Multi-Agent Orchestration & Feedback Loop (Weeks 19–22)

### Week 19–20: Full Integration

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Complete LangGraph with all termination conditions | B | Graph handles: flag found, budget exceeded, no paths |
| Replanning: failure context fed back to exploit agent | B | Second attempt uses different module |
| Report generator: HTML report from attack graph | D | Report renders with topology + timeline |

### Week 21–22: Validation

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Test on 3 easy HTB machines | C | Results logged to SQLite |
| Test on 2 medium HTB machines | C | Results logged to SQLite |
| Cloud API call count analysis | A | Router is reducing cloud calls vs baseline |
| Evaluation metrics computed (SR, PR, TTFS) | D | Metrics table generated |

**Checkpoint:** System validated on 5 machines. Metrics table complete.

---

## Phase 5 — Evaluation (Weeks 23–28)

### Week 23–24: Baseline Setup

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| PentestGPT baseline reproduced on same targets | A | Results logged |
| Ablation flags implemented (`--no-router`, `--no-graph`, `--no-verify`) | B | Each flag disables component correctly |
| Evaluation script: automated batch runner | C | Runs all targets + conditions + logs |

### Week 25–26: Full Evaluation

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| 8 HTB machines evaluated (3 easy, 3 medium, 2 hard) | C | All results in SQLite |
| 5 AutoPenBench in-vitro tasks | C | Results comparable to published |
| 5 ablation conditions × 8 targets × 3 runs | ALL | 120 runs complete |

### Week 27–28: Analysis

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| SR, PR, TTFS computed per condition | D | Tables + charts generated |
| Comparison table vs baselines | D | PentestGPT + manual + no-LLM compared |
| Statistical variance analysis (3 runs) | D | Mean + std for each metric |
| Contamination control documentation | D | HTB release dates vs model cutoffs verified |

**Checkpoint:** All evaluation data collected. Draft results section written.

**If evaluation incomplete:**
- Minimum: 5 targets × 3 conditions = 15 runs (reduce ablation scope)
- Paper frames as "preliminary evaluation" instead of "comprehensive benchmark"

---

## Phase 6 — Paper & Optimization (Weeks 29–32)

### Week 29–30: Writing

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Introduction + Related Work | D | 4 pages draft |
| Architecture + Implementation | B | 3 pages draft with diagrams |
| LLM Analysis (routing effectiveness) | A | 2 pages with routing decision analysis |
| Evaluation + Results | C | 3 pages with tables + charts |
| Abstract + Conclusion | ALL | Finalized |

### Week 31–32: Polish

| Deliverable | Owner | Done When |
|-------------|-------|-----------|
| Paper reviewed by all members | ALL | Zero unresolved comments |
| GitHub repo cleaned and documented | B | README complete, code commented |
| System demo video recorded | ALL | 5-min walkthrough video |
| Paper submitted to target venue | ALL | Submission confirmed |
| Router thresholds calibrated based on eval data | A | Final thresholds documented |

---

## Mandatory Weekly Process

### Weekly Standup (1 hour, fixed day)

Agenda:
1. Each member: what did you deliver, what's blocked, what's next (5 min each)
2. GitHub Projects board review (10 min)
3. Blocker resolution (20 min)
4. Next week commitments (10 min)

### Weekly Artifacts

Each member must produce by standup:
- Updated GitHub Issues (status + time spent)
- At least 1 PR merged (or justified reason for none)
- Updated task completion in Projects board

### Consequence Rules

| Violation | First | Second | Third |
|-----------|-------|--------|-------|
| Missed weekly deliverable | Documented in standup | Peer pair-programming assigned | Escalate to supervisor |
| No standup attendance | Async update required within 24h | Warning documented | Role responsibilities reviewed |
| PR blocked CI for >48h | Must fix immediately | Code review session assigned | Loss of merge privileges |
| Scope creep proposal | Discuss + vote | Document as future work | Rejected automatically |

---

*This timeline is a contract. Deviations require documented justification and team consensus.*
