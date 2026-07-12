# PrivacyAware-PenAgent

> **A Hybrid Local/Cloud LLM Orchestration System for Autonomous Penetration Testing with Persistent Attack State Management**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)]()
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)]()

---

## Overview

PrivacyAware-PenAgent is an autonomous penetration testing system addressing two critical gaps:

1. **Open-Source LLM Performance Collapse** — Runtime routing between local (Ollama) and cloud (GPT-4o) LLMs based on data sensitivity and task complexity
2. **Context Loss Across Attack Stages** — Persistent NetworkX-based attack graph surviving context resets

Built on 10 papers (2023–2024) including PentestGPT (USENIX Security 2024), CHECKMATE, HackSynth, and AutoPenBench.

**Target Venues:** ACSAC, NDSS Workshop on AI Security, IEEE S&P Workshop

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   ORCHESTRATOR (LangGraph)                │
└──────────┬───────────────────────────────┬───────────────┘
    ┌──────▼──────┐                 ┌──────▼──────┐
    │ RECON AGENT │                 │EXPLOIT AGENT│
    │ Nmap+Gobust │                 │ MSF RPC     │
    └──────┬──────┘                 └──────┬──────┘
           └──────────────┬────────────────┘
                 ┌────────▼────────┐
                 │  ATTACK GRAPH   │
                 │ NetworkX+SQLite │
                 └────────┬────────┘
                 ┌────────▼────────┐
                 │   LLM ROUTER    │
                 └───┬─────────┬───┘
              ┌──────▼──┐  ┌───▼──────┐
              │LOCAL LLM│  │CLOUD LLM │
              │ Ollama  │  │GPT-4o    │
              └─────────┘  └──────────┘
                 ┌────────▼────────┐
                 │  VERIFICATION   │
                 │  & REPORTING    │
                 └─────────────────┘
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for full deep-dive.

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Kali Linux | 2024.1+ | Base OS |
| Python | 3.10+ | Runtime |
| Ollama | Latest | Local LLM |
| Metasploit | 6.3+ | Exploitation |
| Nmap | 7.94+ | Recon |
| Gobuster | 3.6+ | Web enum |

---

## Setup

### 1. Clone & Environment

```bash
git clone https://github.com/<org>/PrivacyAware-PenAgent.git
cd PrivacyAware-PenAgent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3:8b-instruct-q4_K_M
ollama pull mistral:7b-instruct-v0.3-q4_K_M
curl http://localhost:11434/api/tags  # verify
```

### 3. Metasploit RPC

```bash
msfrpcd -P your_rpc_password -S -a 127.0.0.1 -p 55553
```

### 4. Environment Variables

Create `.env` (NEVER commit):

```bash
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
OLLAMA_HOST=http://localhost:11434
MSF_RPC_HOST=127.0.0.1
MSF_RPC_PORT=55553
MSF_RPC_PASSWORD=your_rpc_password
SENSITIVITY_THRESHOLD=0.6
COMPLEXITY_THRESHOLD=0.7
MAX_CLOUD_TOKENS_PER_RUN=50000
MAX_EXPLOIT_RETRIES=3
LOG_LEVEL=INFO
```

### 5. HackTheBox VPN

```bash
sudo openvpn --config lab_<username>.ovpn
ping 10.10.10.1
```

---

## Running

```bash
# Full autonomous run
python -m src.main --target 10.10.11.XXX --mode autonomous

# Interactive/debug mode
python -m src.main --target 10.10.11.XXX --mode interactive

# Recon only
python -m src.main --target 10.10.11.XXX --mode recon-only

# Ablation variants
python -m src.main --target 10.10.11.XXX --no-router --force-cloud
python -m src.main --target 10.10.11.XXX --no-router --force-local
python -m src.main --target 10.10.11.XXX --no-graph
python -m src.main --target 10.10.11.XXX --no-verify
```

---

## Example Flow

```
[10:00:01] INFO  orchestrator: Starting pentest against 10.10.11.230
[10:00:02] INFO  recon_agent: Nmap scan → 4 open ports: 22,80,443,8080
[10:02:15] INFO  recon_agent: Gobuster → 12 web endpoints
[10:03:41] INFO  llm_router: sensitivity=0.3 complexity=0.8 → CLOUD
[10:03:45] INFO  exploit_agent: Recommends apache_activemq_rce (0.92)
[10:03:55] CRITICAL verify: Shell obtained! Session 1, user=www-data
[10:04:30] CRITICAL verify: Root shell! Session 2, user=root
[10:04:32] INFO  report: → reports/10.10.11.230_20260424.html
```

---

## Branch Strategy

| Branch | Purpose | Merge To |
|--------|---------|----------|
| `main` | Production releases | — |
| `dev` | Integration | `main` |
| `feature/*` | New work | `dev` |
| `bugfix/*` | Fixes | `dev` |
| `hotfix/*` | Critical | `main`+`dev` |

---

## Contribution

1. Pick task from GitHub Projects ("Ready" column)
2. Create branch from `dev`: `feature/<issue>-<desc>`
3. Follow [CLAUDE.md](./CLAUDE.md) standards
4. Tests ≥70% coverage for changed files
5. PR with template → CI pass + 1 approval → squash-merge

---

## Project Structure

```
src/
├── agents/         # Recon, Exploit, Verification, Orchestrator
├── router/         # LLM routing logic
├── state/          # Attack graph + persistence
├── tools/          # Nmap, Gobuster, Metasploit wrappers
├── reporting/      # Report generation
├── config/         # Settings, prompts
└── main.py
tests/
├── unit/
├── integration/
└── conftest.py
```

---

## Team

| Role | Member | Responsibility |
|------|--------|---------------|
| Member A | **Prajyot** | LLM/AI — Router, prompts, benchmarking |
| Member B | **Vighnesh** | Backend — LangGraph, orchestration |
| Member C | **Vedant** | Security Lead — Nmap, Metasploit, exploits, evaluation |
| Member D | **Parth** | Data — Attack graph, persistence, reports |

---

*Capstone project — Vidyalankar Institute of Technology*
*Repository maintained by Vedant ([@VSP-Vedant](https://github.com/VSP-Vedant))*
