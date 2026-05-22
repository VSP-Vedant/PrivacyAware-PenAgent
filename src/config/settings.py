"""Project-wide settings for PrivacyAware-PenAgent.

Loads configuration from .env file and provides centralized
access to all project settings and constants.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


# --- LLM Configuration ---
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# --- Metasploit RPC ---
MSF_RPC_HOST: str = os.getenv("MSF_RPC_HOST", "127.0.0.1")
MSF_RPC_PORT: int = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_PASSWORD: str = os.getenv("MSF_RPC_PASSWORD", "")

# --- Router Thresholds ---
SENSITIVITY_THRESHOLD: float = float(
    os.getenv("SENSITIVITY_THRESHOLD", "0.6")
)
COMPLEXITY_THRESHOLD: float = float(
    os.getenv("COMPLEXITY_THRESHOLD", "0.7")
)

# --- Budget Limits ---
MAX_CLOUD_TOKENS_PER_RUN: int = int(
    os.getenv("MAX_CLOUD_TOKENS_PER_RUN", "50000")
)
MAX_EXPLOIT_RETRIES: int = int(
    os.getenv("MAX_EXPLOIT_RETRIES", "3")
)
MAX_TOTAL_STEPS: int = int(
    os.getenv("MAX_TOTAL_STEPS", "100")
)

# --- Logging ---
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_DIR: str = os.getenv("LOG_DIR", str(_PROJECT_ROOT / "logs"))

# --- Target Validation ---
ALLOWED_TARGET_RANGES: list[str] = [
    "10.10.0.0/16",       # HackTheBox VPN range
    "10.129.0.0/16",      # HackTheBox VPN range (alternate)
    "192.168.56.0/24",    # Local VirtualBox host-only
    "172.17.0.0/16",      # Docker containers
    "127.0.0.1/32",       # Localhost
]
