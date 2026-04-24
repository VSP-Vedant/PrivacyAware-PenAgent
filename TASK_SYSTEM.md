# TASK_SYSTEM.md — Task Management Rules

> **Every piece of work is tracked. Untracked work does not exist.**

---

## 1. Hierarchy

```
EPIC (Phase-level goal)
  └── TASK (Feature/component deliverable, 1–5 days)
        └── SUBTASK (Atomic unit of work, <1 day)
```

### Epic
- Maps 1:1 to a project phase
- Created at start of phase
- Contains all tasks for that phase
- GitHub: Milestone

### Task
- Maps to a GitHub Issue
- Has exactly ONE owner
- Has acceptance criteria
- Has time estimate
- GitHub: Issue with labels

### Subtask
- Maps to a checklist item within an Issue
- Tracked as `- [ ]` in issue body
- No separate issue needed unless >4 hours

---

## 2. Assignment Rules

| Rule | Enforcement |
|------|-------------|
| Every task has exactly 1 owner | GitHub issue assignee (singular) |
| Owner must match TEAM_ROLES.md | Reviewer checks on PR |
| No task assigned to >1 person | If pair work needed, create 2 subtasks |
| Unassigned tasks cannot enter "Ready" | Projects board automation |
| Owner cannot reassign without standup discussion | Documented in meeting notes |

---

## 3. Time Estimation

| Size | Hours | Label |
|------|-------|-------|
| XS | <2h | `size/xs` |
| S | 2–4h | `size/s` |
| M | 4–8h | `size/m` |
| L | 1–2 days | `size/l` |
| XL | 3–5 days | `size/xl` |

**Rules:**
- Every task MUST have a size label before entering "Ready"
- If actual time exceeds estimate by >2×, post-mortem in standup
- XL tasks should be split into smaller tasks where possible

---

## 4. Status Lifecycle

```
BACKLOG → READY → IN PROGRESS → IN REVIEW → DONE
                       ↓              ↓
                    BLOCKED         CHANGES REQUESTED
                       ↓              ↓
                  (unblock) → IN PROGRESS → IN REVIEW → DONE
```

| Status | Entry Criteria | Exit Criteria |
|--------|---------------|---------------|
| Backlog | Issue created | Scoped + estimated + assigned |
| Ready | Has owner, estimate, acceptance criteria | Work begins |
| In Progress | Branch created | PR submitted |
| In Review | PR opened, CI passing | Approved by reviewer(s) |
| Done | PR merged | — |
| Blocked | Dependency identified | Blocker resolved |

**Rules:**
- Maximum 2 tasks "In Progress" per member at any time
- Task in "In Progress" >5 days without PR → flagged in standup
- "Blocked" tasks must have linked blocking issue

---

## 5. Review and Approval Flow

```
1. Author creates PR linking issue ("Closes #N")
2. CI runs automatically (lint, test, security, build)
3. If CI fails → Author fixes → push → CI reruns
4. If CI passes → Reviewer assigned automatically
5. Reviewer checks:
   a. Code quality (CLAUDE.md standards)
   b. Module ownership (TEAM_ROLES.md)
   c. Tests present and meaningful
   d. No security violations
6. Reviewer: Approve OR Request Changes
7. If changes requested → Author fixes → re-request review
8. If approved → Squash merge → Delete branch → Issue closes
```

**Review SLA:**
- Reviewer must respond within 24 hours (business days)
- If no response in 24h → author pings in team chat
- If no response in 48h → any other member can review

---

## 6. Sample Tasks

### Phase 1 Epic: "Environment Setup & Architecture Lock"

#### Task 1.1: Kali VM Configuration
```
Title: [FEAT] Configure Kali VM with all required tools
Owner: Member C
Size: M (4-8h)
Labels: phase-1, member-c, size/m

Acceptance Criteria:
- [ ] Kali Linux VM running (VirtualBox or VMware)
- [ ] Nmap 7.94+ installed and functional
- [ ] Gobuster 3.6+ installed and functional
- [ ] Metasploit Framework 6.3+ installed
- [ ] msfrpcd starts without errors
- [ ] Python 3.10+ available
- [ ] Screenshot of all tools running posted in issue

Subtasks:
- [ ] Install/update Kali
- [ ] Verify Nmap version and test scan
- [ ] Verify Gobuster and test enumeration
- [ ] Start msfrpcd and verify RPC port
- [ ] Install Python 3.10+ if not present
```

#### Task 1.2: Ollama + Local LLM Setup
```
Title: [FEAT] Install Ollama and pull Llama3 8B + Mistral 7B
Owner: Prajyot
Size: M (4-8h)

Acceptance Criteria:
- [ ] Ollama installed and running
- [ ] llama3:8b-instruct model pulled
- [ ] mistral:7b-instruct model pulled
- [ ] Latency benchmark on 5 pentest prompts documented
- [ ] GPU VRAM usage logged
- [ ] Results in docs/llm_benchmarks.md
```

#### Task 1.3: LangGraph Skeleton
```
Title: [FEAT] Implement LangGraph state graph skeleton
Owner: Vighnesh
Size: L (1-2 days)

Acceptance Criteria:
- [ ] StateGraph with 3 nodes (recon, exploit, verify)
- [ ] 1 conditional edge (should_exploit)
- [ ] PenTestState TypedDict defined
- [ ] Graph compiles and runs with mock agents
- [ ] Unit test verifying graph execution order
```

### Phase 2 Epic: "Core Agent Development"

#### Task 2.1: Nmap XML Parser
```
Title: [FEAT] Implement Nmap XML parser with service extraction
Owner: Vedant
Size: M (4-8h)

Acceptance Criteria:
- [ ] Parses Nmap XML output → list[ServiceInfo]
- [ ] Extracts: port, protocol, service name, version, state
- [ ] Handles OS detection output
- [ ] Unit tests with 3 sample XML files
- [ ] Coverage ≥80%
```

#### Task 2.2: Attack Graph Core
```
Title: [FEAT] Implement NetworkX attack graph with SQLite persistence
Owner: Parth
Size: XL (3-5 days)

Acceptance Criteria:
- [ ] NetworkX DiGraph with typed nodes (host, service, cve, session)
- [ ] Typed edges (hosts_service, vulnerable_to, exploit_attempt)
- [ ] SQLite serialize/deserialize round-trip works
- [ ] query: get_exploitable_services()
- [ ] query: get_failed_exploits(service_id)
- [ ] Unit tests for all operations
- [ ] Coverage ≥70%
```

### Phase 3 Epic: "Exploitation Agent"

#### Task 3.1: Metasploit RPC Integration
```
Title: [FEAT] Implement Metasploit RPC wrapper
Owner: Vedant
Size: L (1-2 days)

Acceptance Criteria:
- [ ] Connect to msfrpcd via pymetasploit3
- [ ] modules.search(query) works
- [ ] module.execute(module, options, payload) works
- [ ] sessions.list returns active sessions
- [ ] Error handling for connection failures
- [ ] Integration test against Metasploitable VM
```

#### Task 3.2: Exploit Selection Prompt
```
Title: [FEAT] Design and test exploit selection prompt template
Owner: Prajyot
Size: M (4-8h)

Acceptance Criteria:
- [ ] System prompt for exploit selection defined
- [ ] Structured output schema enforced (module_path, options, payload)
- [ ] Tested with 5 service/CVE inputs against GPT-4o
- [ ] Tested with same inputs against Llama3 8B
- [ ] Results compared and documented
- [ ] Prompt template in src/config/prompts.py
```

---

## 7. Task Creation Checklist

Before moving any task to "Ready":

- [ ] Title follows format: `[TYPE] <description>`
- [ ] Owner assigned (single person)
- [ ] Size label applied
- [ ] Phase label applied
- [ ] Acceptance criteria defined (measurable)
- [ ] Dependencies identified (blocked-by links)
- [ ] Subtasks listed if task is L or XL

---

*If it's not in an issue, it's not being tracked. If it's not tracked, it doesn't count.*
