"""Sensitivity classifier for LLM routing. Member A owned.

Classifies task input based on presence of sensitive data patterns.
Conservative: defaults to higher score if ambiguous.
"""

import re
from typing import List, Tuple

# Weighted sensitive patterns (higher weight = more sensitive)
SENSITIVE_PATTERNS: List[Tuple[str, float]] = [
    # Network / Target identifiers
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.45),  # IP addresses
    (r"\b10\.(?:10|129)\.\d{1,3}\.\d{1,3}\b", 0.55),  # HTB ranges
    (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", 0.45),  # IPv6
    # Credentials & Secrets
    (r"(?i)(password|passwd|pwd|credential|secret|key|api_key|token)", 0.5),
    (r"(?i)session_id|auth_token|jwt|cookie|flag\{.*?\}", 0.55),
    # File paths & system info
    (r"/(?:etc|var|home|root|tmp|usr)/", 0.4),
    (r"\b(?:root|admin|user|www-data):\S+", 0.45),
    # Privilege / Command output
    (r"(?i)(uid=0|root|admin|whoami|id |uname)", 0.35),
    # Service banners / versions
    (r"(?i)(apache|nginx|openssh|vsftpd|mysql|postgresql|smb|rdp)[\s/]\d", 0.3),
]


def classify_sensitivity(task_input: str) -> float:
    """Score sensitivity from 0.0 (safe) to 1.0 (highly sensitive)."""
    if not task_input or len(task_input.strip()) == 0:
        return 0.0

    score = 0.0
    for pattern, weight in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, task_input, re.IGNORECASE)
        if matches:
            score += weight * len(matches)

    normalized = min(1.0, score / 2.0)
    return round(normalized, 2)
