# RISK_REGISTER.md — Expanded Risk Management

> **Every risk has a trigger, impact, mitigation, and fallback. No surprises.**

---

## Technical Risks

### T1: Metasploit RPC Instability

| Field | Detail |
|-------|--------|
| **Trigger** | msfrpcd crashes, drops connections, or fails to start |
| **Likelihood** | Medium |
| **Impact** | HIGH — Exploit Agent cannot function |
| **Mitigation** | Health check before each run. Auto-restart script. Connection pooling with retry logic (3 attempts, exponential backoff) |
| **Fallback** | Direct `msfconsole -x` subprocess calls with output parsing. Slower but functional |
| **Owner** | Member C |
| **Detection** | CI integration test against mock RPC. Runtime health check logs |

### T2: LLM Hallucination of Non-Existent Modules

| Field | Detail |
|-------|--------|
| **Trigger** | LLM returns Metasploit module name that doesn't exist |
| **Likelihood** | HIGH |
| **Impact** | Medium — wasted tokens, failed exploit attempt |
| **Mitigation** | Validate ALL module names against `modules.search` before execution. Maintain allowlist of known-good modules. Track hallucination rate |
| **Fallback** | SearchSploit lookup. If no exploit found, mark service as "no automated exploit available" and move to next |
| **Owner** | Member A (prompt), Member C (validation) |
| **Detection** | Hallucination counter in logs. Alert if rate >20% |

### T3: Ollama GPU Memory Exhaustion

| Field | Detail |
|-------|--------|
| **Trigger** | Consumer GPU (8–12 GB VRAM) runs out of memory during inference |
| **Likelihood** | Medium |
| **Impact** | Medium — local LLM calls fail, all traffic routes to cloud |
| **Mitigation** | Use quantized models (Q4_K_M). Monitor VRAM usage. Set `num_gpu` layers appropriately. Kill other GPU processes |
| **Fallback** | CPU-only inference (slower, ~10x latency). Or force cloud routing with budget warning |
| **Owner** | Member A |
| **Detection** | Ollama error logs. VRAM monitoring in system metrics |

### T4: Nmap Scan Duration on Remote Targets

| Field | Detail |
|-------|--------|
| **Trigger** | HackTheBox targets have ~200ms RTT, scans take 10+ minutes |
| **Likelihood** | HIGH |
| **Impact** | Low — delays but doesn't break pipeline |
| **Mitigation** | Use targeted scans (`-p-` only for full eval, top-1000 for dev). Cache scan results. Parallel scan + parse |
| **Fallback** | Reduce port range. Use previous scan cache for re-runs |
| **Owner** | Member C |
| **Detection** | Scan duration logged. Alert if >15 minutes |

### T5: NetworkX Graph Performance at Scale

| Field | Detail |
|-------|--------|
| **Trigger** | Attack graph exceeds 1000 nodes (unlikely for single-host targets) |
| **Likelihood** | LOW |
| **Impact** | Low — query latency increases |
| **Mitigation** | Profile graph operations. Index critical queries. Lazy loading for large graphs |
| **Fallback** | Switch to SQLAlchemy relational model if needed |
| **Owner** | Member D |
| **Detection** | Graph size logged after each mutation. Performance benchmarks in tests |

### T6: LangGraph State Machine Infinite Loops

| Field | Detail |
|-------|--------|
| **Trigger** | Exploit → verify → replan cycle never terminates |
| **Likelihood** | Medium |
| **Impact** | HIGH — system hangs, burns cloud tokens |
| **Mitigation** | Hard step budget (MAX_TOTAL_STEPS=100). Per-service retry cap (3). Negative edge tracking (never retry same module+payload). Run-level timeout (30 min) |
| **Fallback** | Kill process. Analyze attack graph post-mortem for loop cause |
| **Owner** | Member B |
| **Detection** | Step counter in orchestrator. Alert at 80% of budget |

### T7: NVD API Rate Limiting

| Field | Detail |
|-------|--------|
| **Trigger** | python-nvdlib exceeds NVD API rate limits (5 req/30s without key) |
| **Likelihood** | HIGH |
| **Impact** | Medium — CVE lookup fails, exploit selection degraded |
| **Mitigation** | Request NVD API key (free, 50 req/30s). Aggressive caching (SQLite CVE cache). Batch queries |
| **Fallback** | Local ExploitDB CSV via `searchsploit --json`. Slower but no rate limit |
| **Owner** | Member C |
| **Detection** | HTTP 429 responses logged. Cache hit rate monitored |

### T8: Python Dependency Conflicts

| Field | Detail |
|-------|--------|
| **Trigger** | LangGraph, pymetasploit3, python-nmap have incompatible transitive dependencies |
| **Likelihood** | Medium |
| **Impact** | Medium — blocks development |
| **Mitigation** | Pin all versions in requirements.txt. Use `pip-compile` for dependency resolution. Test in clean venv weekly |
| **Fallback** | Isolate conflicting packages in separate venvs with subprocess calls |
| **Owner** | Member B |
| **Detection** | CI installs from clean venv every run |

---

## Team Risks

### P1: Member Underperformance

| Field | Detail |
|-------|--------|
| **Trigger** | Member misses 3+ consecutive weekly deliverables |
| **Likelihood** | Medium |
| **Impact** | HIGH — blocked dependencies, timeline slip |
| **Mitigation** | Weekly standups with accountability. Pair programming for struggling members. Early escalation |
| **Fallback** | Redistribute responsibilities per TEAM_ROLES.md replacement protocol |
| **Owner** | ALL |
| **Detection** | GitHub Projects board shows stale "In Progress" items. PR frequency drops |

### P2: Knowledge Silos

| Field | Detail |
|-------|--------|
| **Trigger** | Only one person understands a critical module |
| **Likelihood** | HIGH |
| **Impact** | HIGH — bus factor = 1 for each module |
| **Mitigation** | Mandatory code review by non-owner. Documentation requirements in DoD. Knowledge sharing in standups |
| **Fallback** | Documented codebase + tests make handover possible in 1–2 days |
| **Owner** | ALL |
| **Detection** | Review rotation tracking. If same reviewer always reviews same module → flag |

### P3: Communication Breakdown

| Field | Detail |
|-------|--------|
| **Trigger** | Members work in isolation, integration fails |
| **Likelihood** | Medium |
| **Impact** | HIGH — integration phase reveals incompatible interfaces |
| **Mitigation** | Define interfaces (schemas, function signatures) in Phase 1. Integration tests from Phase 2. Weekly integration check |
| **Fallback** | Emergency integration sprint with all members co-located |
| **Owner** | Member B (integration lead) |
| **Detection** | Integration tests failing. Merge conflicts increasing |

### P4: Exam/Academic Conflicts

| Field | Detail |
|-------|--------|
| **Trigger** | University exam periods reduce availability |
| **Likelihood** | HIGH |
| **Impact** | Medium — 2–3 week productivity drops |
| **Mitigation** | Identify exam periods in advance. Front-load work before exams. Reduce sprint scope during exam weeks |
| **Fallback** | 4-week buffer built into 32-week timeline |
| **Owner** | ALL |
| **Detection** | Calendar planning at project start |

---

## Timeline Risks

### R1: Scope Creep

| Field | Detail |
|-------|--------|
| **Trigger** | Team adds features not in original architecture |
| **Likelihood** | HIGH |
| **Impact** | HIGH — delays core deliverables |
| **Mitigation** | Architecture locked after Week 6. Changes require supervisor approval + unanimous vote. New ideas → "future work" section |
| **Fallback** | Cut to MVP scope. Router + graph are sufficient thesis contribution |
| **Owner** | ALL |
| **Detection** | New issues not matching IMPLEMENTATION_PLAN.md flagged |

### R2: Phase Dependency Cascading Delay

| Field | Detail |
|-------|--------|
| **Trigger** | Phase 2 delays push Phase 3, which pushes Phase 4... |
| **Likelihood** | Medium |
| **Impact** | HIGH — evaluation phase compressed or eliminated |
| **Mitigation** | 2-week buffer per phase. Parallel work where possible (router + graph in Phase 2). MVP checkpoint at Week 12 |
| **Fallback** | Reduce evaluation scope (5 targets × 3 conditions instead of 8 × 5). Frame as "preliminary evaluation" |
| **Owner** | Member B (timeline tracker) |
| **Detection** | Milestone dates tracked in GitHub Projects. Slippage visible in board |

### R3: Evaluation Infrastructure Failure

| Field | Detail |
|-------|--------|
| **Trigger** | HackTheBox VPN instability, machines retired, API changes |
| **Likelihood** | Medium |
| **Impact** | HIGH — cannot collect evaluation data |
| **Mitigation** | Maintain local Metasploitable VMs as backup targets. Cache HTB machine data. Record all runs for reproducibility |
| **Fallback** | Evaluate on AutoPenBench in-vitro tasks only (deterministic, local). Supplement with local vulnerable VMs |
| **Owner** | Member C |
| **Detection** | VPN connectivity test before evaluation sprint. HTB machine availability check |

---

## AI/LLM Risks

### L1: Cloud API Cost Overrun

| Field | Detail |
|-------|--------|
| **Trigger** | GPT-4o calls exceed budget (₹3,000–5,000/month) |
| **Likelihood** | Medium |
| **Impact** | Medium — budget exhausted, evaluation incomplete |
| **Mitigation** | Per-run token budget (50K cloud tokens). Cost logged after each run. Optimize prompt length. Reserve cloud for high-complexity only |
| **Fallback** | Switch to GPT-4o-mini for evaluation runs. Or Claude Haiku as cheaper alternative |
| **Owner** | Member A |
| **Detection** | Cost dashboard updated daily during evaluation phase |

### L2: Model API Deprecation or Changes

| Field | Detail |
|-------|--------|
| **Trigger** | OpenAI deprecates `gpt-4o-2024-11-20` or changes pricing |
| **Likelihood** | Low (within 8 months) |
| **Impact** | Medium — need to switch models, recalibrate prompts |
| **Mitigation** | Abstract LLM calls behind interface. Support multiple providers (OpenAI + Anthropic). Pin model version |
| **Fallback** | Claude Sonnet as drop-in replacement. Test prompts on both providers in Phase 2 |
| **Owner** | Member A |
| **Detection** | Monitor OpenAI/Anthropic announcements monthly |

### L3: Local Model Quality Insufficient

| Field | Detail |
|-------|--------|
| **Trigger** | Llama3 8B produces unusable output for tasks routed locally |
| **Likelihood** | Medium |
| **Impact** | Medium — defeats purpose of hybrid routing |
| **Mitigation** | Benchmark local models on pentest-specific tasks in Phase 1. Calibrate routing thresholds based on actual performance. Fine-tune prompts for local models |
| **Fallback** | Raise complexity threshold (more goes to cloud). Or use Mistral 7B as alternative local model. Accept higher cloud costs |
| **Owner** | Member A |
| **Detection** | Local model output quality scored in Phase 2 benchmarks |

### L4: Prompt Injection via Tool Output

| Field | Detail |
|-------|--------|
| **Trigger** | Target system returns crafted output that manipulates LLM behavior |
| **Likelihood** | Low (CTF targets unlikely) |
| **Impact** | Medium — LLM takes unintended actions |
| **Mitigation** | Sanitize all tool output before passing to LLM. Separate system prompt from tool output. Validate LLM output against allowed actions |
| **Fallback** | Hard-code allowed actions list. LLM can only suggest, never execute directly |
| **Owner** | Member A (prompt), Member B (execution control) |
| **Detection** | Anomalous LLM outputs logged. Action validation in orchestrator |

---

## Risk Review Schedule

| When | What |
|------|------|
| Weekly standup | Review any triggered risks |
| End of each phase | Full risk register review. Update likelihoods |
| After any incident | Post-mortem → add new risk if novel |
| Week 12 (MVP) | Major risk reassessment. Update fallback plans |

---

*Risks are not predictions — they are preparation. Every risk with mitigation is a risk managed.*
