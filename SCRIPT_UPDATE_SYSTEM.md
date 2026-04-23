# SCRIPT_UPDATE_SYSTEM.md — Legacy Script Refactoring System

> **When old scripts arrive, analyze → compare → refactor → output clean code.**
> **No manual guessing. Systematic transformation.**

---

## 1. Purpose

When a team member uploads OLD scripts (from prior work, tutorials, or prototypes), this system:

1. Analyzes the script structure
2. Compares against PrivacyAware-PenAgent architecture requirements
3. Identifies gaps, deprecated patterns, and non-compliant code
4. Refactors into the new architecture-compliant format

---

## 2. Input Expectations

### Accepted Inputs

| Type | Extension | Example |
|------|-----------|---------|
| Python scripts | `.py` | Old nmap scanner, exploit runner |
| Shell scripts | `.sh` | Setup scripts, tool wrappers |
| Jupyter notebooks | `.ipynb` | Prototype/research code |
| Config files | `.yaml`, `.json`, `.toml` | Old configuration |

### Required Metadata

When uploading a script for refactoring, provide:

```yaml
script_name: old_nmap_scan.py
original_purpose: "Runs nmap and prints results"
target_module: src/tools/nmap_wrapper.py  # Where it maps in new architecture
author: Member C
date_written: 2025-06-15
dependencies: [python-nmap, subprocess]
```

---

## 3. Analysis Phase

### Step 1: Structure Analysis

The system inspects:

| Check | What It Looks For |
|-------|------------------|
| **Imports** | Which libraries used, are they in requirements.txt? |
| **Functions** | Function signatures, return types, docstrings present? |
| **Classes** | Class hierarchy, methods, state management |
| **Global state** | Module-level variables, singletons |
| **Entry point** | `if __name__ == "__main__"` usage |
| **Error handling** | try/except patterns, bare exceptions |
| **Logging** | print() vs logging module |
| **Config** | Hardcoded values vs environment variables |
| **I/O** | File reads/writes, network calls, subprocess usage |

### Step 2: Architecture Compliance Check

Compare against ARCHITECTURE.md requirements:

```
COMPLIANCE CHECKLIST:
□ Uses logging module (not print)
□ Type hints on all functions
□ Google-style docstrings
□ No hardcoded credentials/IPs
□ Returns structured data (dataclass/TypedDict)
□ Has corresponding test file
□ Follows naming conventions (snake_case functions, PascalCase classes)
□ Error handling with specific exceptions
□ No bare except clauses
□ Max line length 88 (black compatible)
□ Imports sorted (isort compatible)
□ No mutable default arguments
□ Uses f-strings (not .format or %)
□ Target validation present (for tool wrappers)
```

---

## 4. Diff Logic

### Identification Rules

| Finding | Category | Priority |
|---------|----------|----------|
| `print()` statements | **Non-compliant** | HIGH — must replace with logging |
| No type hints | **Missing component** | HIGH — must add |
| No docstrings | **Missing component** | MEDIUM — must add |
| Hardcoded IPs/paths | **Security violation** | CRITICAL — must parameterize |
| Bare `except:` | **Non-compliant** | HIGH — must specify exception |
| No return type annotation | **Missing component** | HIGH — must add |
| `subprocess.call` without timeout | **Deprecated logic** | MEDIUM — add timeout |
| Global mutable state | **Non-compliant** | MEDIUM — refactor to class |
| No input validation | **Missing component** | HIGH — add validation |
| `.format()` string formatting | **Deprecated logic** | LOW — convert to f-string |
| Missing `__init__.py` awareness | **Non-compliant** | LOW — ensure module importable |
| Raw dict returns | **Non-compliant** | MEDIUM — use dataclass |

### Diff Report Format

```markdown
## Script Analysis: old_nmap_scan.py

### Summary
- Lines of code: 145
- Functions: 6
- Classes: 0
- Compliance score: 3/14 (21%)

### Critical Issues (must fix)
1. Line 12: Hardcoded IP `192.168.1.1` → use config/env variable
2. Line 45: `print(results)` → `logger.info(results)`
3. Lines 67-89: Bare `except:` → `except (NmapError, TimeoutError):`

### Missing Components (must add)
4. No type hints on any function
5. No docstrings
6. No return type annotations
7. No input validation on target parameter

### Deprecated Patterns (should fix)
8. Line 23: `"{}".format(port)` → `f"{port}"`
9. Line 91: `subprocess.call` → `subprocess.run` with timeout
10. Returns raw dicts → use `@dataclass`

### Architecture Mapping
- Current: standalone script
- Target: `src/tools/nmap_wrapper.py`
- Integration: Called by `src/agents/recon_agent.py`
- Must implement: `NmapWrapper` class with `scan()` method
```

---

## 5. Refactoring Rules

### Rule 1: Structural Transformation

```
OLD: Standalone script with if __name__ == "__main__"
NEW: Class-based module importable by agents

OLD: Global functions
NEW: Methods on a class with dependency injection

OLD: Raw subprocess calls
NEW: Wrapped in class with error handling, timeout, logging
```

### Rule 2: Interface Compliance

Every tool wrapper must implement:

```python
class ToolWrapper:
    """Base interface for all tool wrappers."""

    def __init__(self, config: ToolConfig) -> None:
        """Initialize with configuration."""
        self.config = config
        self.logger = setup_logger(self.__class__.__name__)

    def validate_target(self, target: str) -> bool:
        """Validate target is in allowed ranges."""
        ...

    def execute(self, target: str, **options: Any) -> ToolResult:
        """Execute the tool and return structured result."""
        ...

    def parse_output(self, raw_output: str) -> ParsedOutput:
        """Parse raw tool output into structured format."""
        ...
```

### Rule 3: Error Handling

```python
# OLD (non-compliant)
try:
    result = nmap.scan(target)
except:
    print("scan failed")

# NEW (compliant)
try:
    result = self._nmap.scan(
        target,
        arguments=self.config.scan_arguments,
    )
except nmap.PortScannerError as e:
    self.logger.error(
        "Nmap scan failed",
        extra={"target": target, "error": str(e)},
    )
    raise ReconError(f"Nmap scan failed for {target}") from e
except TimeoutError:
    self.logger.error(
        "Nmap scan timed out",
        extra={"target": target, "timeout": self.config.timeout},
    )
    raise ReconError(f"Nmap scan timed out for {target}")
```

### Rule 4: Output Formatting

```python
# OLD (non-compliant)
return {"port": 80, "service": "http", "version": "Apache 2.4.49"}

# NEW (compliant)
@dataclass
class ServiceInfo:
    """Discovered network service."""

    port: int
    protocol: str
    service: str
    version: str
    state: str

    def to_graph_node(self) -> dict[str, Any]:
        """Convert to attack graph node attributes."""
        return asdict(self)
```

### Rule 5: Logging

```python
# OLD
print(f"Scanning {target}...")
print(f"Found {len(ports)} open ports")

# NEW
self.logger.info(
    "Starting scan",
    extra={"target": target, "scan_type": "tcp_syn"},
)
self.logger.info(
    "Scan complete",
    extra={"target": target, "open_ports": len(ports), "duration_ms": elapsed},
)
```

---

## 6. Output Format

Refactored script output must:

1. **Be a drop-in replacement** for the target module path
2. **Include complete type hints** on all functions
3. **Include Google-style docstrings** on all public methods
4. **Pass black formatting** (`black --check`)
5. **Pass flake8** (zero warnings)
6. **Pass mypy** (`--strict`)
7. **Include a companion test file** skeleton

### Output Template

```python
"""Module description.

This module provides [purpose] for the PrivacyAware-PenAgent system.
Refactored from: [original_script_name]
Original author: [author]
Refactored date: [date]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


@dataclass
class OutputType:
    """Structured output from this module."""

    field1: str
    field2: int


class ModuleName:
    """Main class for [purpose].

    Args:
        config: Configuration for this module.
    """

    def __init__(self, config: ModuleConfig) -> None:
        """Initialize module."""
        self.config = config
        self.logger = setup_logger(self.__class__.__name__)

    def execute(self, input_param: str) -> OutputType:
        """Execute primary operation.

        Args:
            input_param: Description.

        Returns:
            Structured output.

        Raises:
            ModuleError: If operation fails.
        """
        self.logger.info("Starting operation", extra={"input": input_param})
        # Implementation
        ...
```

---

## 7. Refactoring Workflow

```
1. UPLOAD: Member uploads old script + metadata YAML
2. ANALYZE: Run structure analysis (automated or manual)
3. REPORT: Generate diff report with compliance score
4. REFACTOR: Transform following rules above
5. TEST: Write companion test file
6. REVIEW: PR with original script as reference in description
7. MERGE: Refactored module replaces old script
```

### Automation Script

Place in `scripts/analyze_script.py`:

```python
"""Analyze a script for architecture compliance.

Usage: python scripts/analyze_script.py path/to/old_script.py
"""

import ast
import sys
from pathlib import Path


def analyze(filepath: str) -> dict:
    """Analyze Python script for compliance issues."""
    source = Path(filepath).read_text()
    tree = ast.parse(source)

    issues = []
    stats = {
        "lines": len(source.splitlines()),
        "functions": 0,
        "classes": 0,
        "prints": 0,
        "bare_excepts": 0,
        "type_hints": 0,
        "no_type_hints": 0,
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            stats["functions"] += 1
            if node.returns:
                stats["type_hints"] += 1
            else:
                stats["no_type_hints"] += 1
                issues.append(f"Line {node.lineno}: {node.name}() missing return type")

        elif isinstance(node, ast.ClassDef):
            stats["classes"] += 1

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                stats["prints"] += 1
                issues.append(f"Line {node.lineno}: print() → use logging")

        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                stats["bare_excepts"] += 1
                issues.append(f"Line {node.lineno}: bare except → specify exception")

    return {"stats": stats, "issues": issues}


if __name__ == "__main__":
    result = analyze(sys.argv[1])
    print(f"Stats: {result['stats']}")
    print(f"Issues ({len(result['issues'])}):")
    for issue in result["issues"]:
        print(f"  - {issue}")
```

---

*Old code is debt. This system converts debt into assets systematically.*
