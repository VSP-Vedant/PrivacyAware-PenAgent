"""Sensitivity Classifier for PrivacyAware-PenAgent.

This module provides keyword and regex-based sensitivity scoring logic.
It determines if an input/output contains sensitive information like IP
addresses, credentials, private paths, or session tokens.
"""

from __future__ import annotations

import re
from typing import TypedDict
from src.utils.logging_config import setup_logger

logger = setup_logger(__name__)


class SensitivityRule(TypedDict):
    """Configuration for a sensitivity classification rule."""

    pattern: re.Pattern[str]
    weight: float
    description: str


# Compilation of regex rules with associated weights
SENSITIVITY_RULES: list[SensitivityRule] = [
    {
        "pattern": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),  # IPv4 Address
        "weight": 0.4,
        "description": "IPv4 Address",
    },
    {
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|pass|pwd|secret|token|api_key|apikey|"
            r"private_key|id_rsa)\s*[:=]\s*['\"a-zA-Z0-9_\-\+]{4,}\b"
        ),
        "weight": 0.9,
        "description": "Credential Pattern",
    },
    {
        "pattern": re.compile(
            r"(?i)\b(?:session_id|sessionid|session|jwt|sid|cookie)\b"
        ),
        "weight": 0.3,
        "description": "Session Keyword",
    },
    {
        "pattern": re.compile(r"\b[a-zA-Z]:\\[a-zA-Z0-9_\.\-\\]+\b"),  # Windows Path
        "weight": 0.3,
        "description": "Windows File Path",
    },
    {
        "pattern": re.compile(
            r"/(?:usr|bin|var|etc|home|tmp|opt|root|lib)/[a-zA-Z0-9_\.\-/]+"
        ),  # Unix Path
        "weight": 0.3,
        "description": "Unix File Path",
    },
    {
        "pattern": re.compile(
            r"(?i)(?:-----BEGIN[ A-Z]+PRIVATE KEY-----|"
            r"\b(?:ssh-rsa|ssh-dss|ecdsa-sha2-nistp|ssh-ed25519)\b)"
        ),  # SSH Key header / private key PEM
        "weight": 1.0,
        "description": "SSH/Private Key Header",
    },
    {
        "pattern": re.compile(r"/etc/(?:passwd|shadow|hosts|shadow)"),  # Linux config
        "weight": 1.0,
        "description": "Critical Linux Config File",
    },
    {
        "pattern": re.compile(
            r"(?i)\b(?:sam|system|security|ntds\.dit)\b"
        ),  # Windows registry hives
        "weight": 0.8,
        "description": "Windows Registry Hive/Database",
    },
    {
        "pattern": re.compile(
            r"(?i)\b(?:administrator|admin|root|SYSTEM|uid=0|gid=0)\b"
        ),  # High-privilege username/tokens
        "weight": 0.4,
        "description": "High Privilege Context",
    },
]


def classify_sensitivity(text: str) -> float:
    """Classify the sensitivity of a text block.

    Scans the text using pre-defined regex rules. Matches add to a cumulative
    score. If a critical rule matches, the score is forced to 1.0. Otherwise,
    the score is capped at 1.0.

    Args:
        text: The text string to analyze.

    Returns:
        A sensitivity score between 0.0 (no sensitivity) and 1.0 (highly sensitive).
    """
    if not text:
        return 0.0

    score = 0.0
    matched_rules: list[str] = []

    for rule in SENSITIVITY_RULES:
        matches = rule["pattern"].findall(text)
        if matches:
            # We add weight once per unique pattern match in the text
            score += rule["weight"]
            matched_rules.append(f"{rule['description']} (x{len(matches)})")

            # Fast-path for critical rules that immediately trigger maximum sensitivity
            if rule["weight"] >= 1.0:
                logger.info(
                    "Critical sensitivity rule triggered",
                    extra={
                        "rule": rule["description"],
                        "score": 1.0,
                    },
                )
                return 1.0

    # Cap the final score at 1.0
    final_score = min(score, 1.0)

    if final_score > 0.0:
        logger.debug(
            "Sensitivity analysis completed",
            extra={
                "score": final_score,
                "matches": matched_rules,
            },
        )

    return final_score
