# VALIDATION_SYSTEM.md — Module Verification

> **Every module has acceptance criteria. Untested code is broken code.**

---

## 1. Recon Agent Validation

### Nmap Parser Correctness

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Open port detection | XML with 5 open ports | 5 `ServiceInfo` objects | Unit test with fixture XML |
| Closed port exclusion | XML with 3 open, 2 closed | 3 objects (closed filtered) | Unit test |
| Service version extraction | `Apache httpd 2.4.49` | `name=httpd, version=2.4.49` | Unit test |
| OS detection parsing | `-O` output | `os_guess` populated | Unit test |
| Malformed XML handling | Truncated XML | Graceful error, not crash | Unit test |
| Empty scan result | No open ports | Empty list, log warning | Unit test |

### CVE Mapping Accuracy

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Known CVE maps correctly | `Apache 2.4.49` | CVE-2021-41773 returned | Integration test with NVD |
| Unknown version returns empty | `CustomApp 0.0.1` | Empty CVE list | Unit test |
| NVD rate limit handling | Rapid 10 queries | Retry with backoff | Integration test |

### Gobuster Correctness

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Endpoint extraction | Gobuster stdout | `WebEndpoint` list | Unit test with fixture output |
| Status code filtering | Mix of 200,301,404 | Only 200,301 kept | Unit test |
| Timeout handling | Hanging target | Timeout after 300s | Integration test |

### Acceptance Criteria

- [ ] All 6 Nmap parser tests pass
- [ ] CVE mapping returns results for ≥3 known vulnerable services
- [ ] Gobuster wrapper handles timeout gracefully
- [ ] 100% of parsed data matches manual verification on 2 sample scans

---

## 2. Exploit Agent Validation

### Module Selection

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Valid module suggested | `Apache ActiveMQ 5.15` | `exploit/multi/http/apache_activemq_rce` | Integration test with LLM |
| Hallucinated module caught | LLM returns fake module | Validation rejects, logs hallucination | Unit test with mock |
| Fallback to searchsploit | No MSF module found | SearchSploit query executed | Integration test |
| Multiple suggestions ranked | Service with 3 CVEs | 3 modules, ranked by confidence | Unit test |

### Metasploit RPC Operations

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Module search | `apache` query | List of matching modules | Integration test (requires MSF) |
| Module execution | Valid module + target | Session or error | Integration test (Metasploitable) |
| Session listing | After successful exploit | Session ID returned | Integration test |
| Connection failure | MSF RPC not running | `ConnectionError` raised | Unit test with mock |
| Timeout handling | Exploit hangs | Timeout after configurable limit | Unit test |

### Acceptance Criteria

- [ ] LLM-suggested modules validated before execution 100% of the time
- [ ] Hallucination rate tracked and logged
- [ ] Successful exploit on Metasploitable VM via RPC
- [ ] SearchSploit fallback activates when MSF module not found

---

## 3. Attack Graph Integrity

### Graph Operations

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Add host node | IP address | Node with type=host | Unit test |
| Add service node | Port + version | Node linked to host | Unit test |
| Add exploit edge | Module + result | Edge with attributes | Unit test |
| Query exploitable services | Graph with mixed nodes | Only services with CVEs | Unit test |
| Query failed exploits | Service with 2 failures | List of 2 post-mortems | Unit test |
| No duplicate nodes | Add same host twice | Single node, no error | Unit test |

### Persistence

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Serialize to SQLite | Graph with 10 nodes | DB file created | Unit test |
| Deserialize from SQLite | Saved DB | Identical graph restored | Unit test |
| Round-trip integrity | Complex graph | `serialize → deserialize → compare` passes | Unit test |
| Concurrent write safety | Two agents writing | No data corruption | Integration test |
| Corrupt DB handling | Truncated SQLite file | Graceful error + new DB | Unit test |

### Acceptance Criteria

- [ ] All graph operations maintain referential integrity
- [ ] Serialize/deserialize round-trip produces identical graph (node-by-node comparison)
- [ ] No data loss after 100 consecutive write operations
- [ ] Query functions return correct results on graph with 50+ nodes

---

## 4. LLM Router Validation

### Routing Correctness

| Test | Input | Expected Route | Method |
|------|-------|---------------|--------|
| Low sensitivity + low complexity | "Format this JSON" | LOCAL | Unit test |
| High sensitivity | Text with IP addresses | CLOUD (sensitivity > 0.6) | Unit test |
| High complexity | Multi-CVE chain task | CLOUD (complexity > 0.7) | Unit test |
| Borderline sensitivity (0.6) | Single IP mention | CLOUD (≥ threshold) | Unit test |
| No sensitive data + simple task | "Summarize output" | LOCAL | Unit test |

### Cost Tracking

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Token count logged | LLM call | Token count in log | Integration test |
| Cost computed | GPT-4o call | USD cost logged | Integration test |
| Budget enforcement | Exceed MAX_CLOUD_TOKENS | Force local routing | Unit test |
| Budget reset per run | New run after budget hit | Budget resets | Unit test |

### Acceptance Criteria

- [ ] Router routes correctly on 50-sample test suite (≥85% accuracy)
- [ ] Sensitive data never sent to cloud when sensitivity > 0.6
- [ ] Cost tracking accurate within 5% of actual API bill
- [ ] Budget enforcement prevents overspend

---

## 5. Verification Agent Validation

| Test | Input | Expected | Method |
|------|-------|----------|--------|
| Shell confirmation | Active session | `verified=true, privilege=user` | Integration test |
| Root detection | Root session | `privilege=root` | Integration test |
| No session | Failed exploit | `verified=false, post_mortem generated` | Unit test |
| Session timeout | Stale session | Timeout detected, logged | Integration test |
| Post-mortem structure | Failed exploit | Valid JSON with all required fields | Unit test |

### Acceptance Criteria

- [ ] 100% of successful exploits correctly verified
- [ ] 100% of failures produce structured post-mortem
- [ ] Post-mortem fed back to attack graph as negative edge
- [ ] Privilege level correctly identified (user vs root)

---

## 6. Debugging Workflow

### When Something Fails

```
1. CHECK LOGS FIRST
   → logs/penagent_<date>.jsonl
   → Search for ERROR and CRITICAL entries
   → Identify the failing module and function

2. REPRODUCE LOCALLY
   → Run the specific agent in isolation
   → python -m pytest tests/unit/test_<module>.py -v --tb=long
   → If integration test: pytest tests/integration/test_<module>.py -m requires_tools

3. ISOLATE THE CAUSE
   → Is it input data? → Check attack graph state
   → Is it tool failure? → Test tool wrapper independently
   → Is it LLM response? → Check prompt + response in logs
   → Is it state corruption? → Check SQLite DB integrity

4. FIX AND VERIFY
   → Write failing test FIRST
   → Fix the code
   → Run full test suite
   → Verify in integration context

5. DOCUMENT
   → Add regression test
   → Update relevant acceptance criteria
   → If novel failure mode → add to RISK_REGISTER.md
```

### Debug Commands

```bash
# Run specific test with verbose output
pytest tests/unit/test_recon_agent.py::test_parses_open_ports -v --tb=long

# Run with debug logging
LOG_LEVEL=DEBUG python -m src.main --target 10.10.11.XXX --mode interactive

# Inspect attack graph state
python -c "from src.state.persistence import load_graph; g = load_graph('runs/latest.db'); print(g.nodes(data=True))"

# Check Metasploit RPC connection
python -c "from src.tools.metasploit_rpc import MsfRpcClient; c = MsfRpcClient(); print(c.modules.search('apache'))"

# Validate router decisions
python -c "from src.router.llm_router import route; print(route('test input', 'SUMMARIZE'))"
```

---

## 7. Logging Standards

### Log Levels

| Level | Use For | Example |
|-------|---------|---------|
| `DEBUG` | Detailed trace info | LLM prompt/response text |
| `INFO` | Normal operations | Agent started, scan complete |
| `WARNING` | Potential issues | Exploit attempt, high latency |
| `ERROR` | Failures requiring attention | Tool crash, parse failure |
| `CRITICAL` | System-level events | Shell obtained, security violation |

### Structured Log Entry

```json
{
  "timestamp": "2026-04-24T10:03:45.123Z",
  "level": "INFO",
  "module": "src.router.llm_router",
  "function": "route",
  "message": "Routing decision made",
  "extra": {
    "task_type": "EXPLOIT_SELECTION",
    "sensitivity_score": 0.3,
    "complexity_score": 0.8,
    "route": "CLOUD",
    "model": "gpt-4o",
    "input_tokens": 450,
    "reasoning": "High complexity exploit chaining task"
  }
}
```

### Log File Rotation

- One file per day: `logs/penagent_YYYYMMDD.jsonl`
- Maximum 30 days retained
- Console output: human-readable, INFO+ only

---

*Untested modules are assumed broken. Verify everything.*
