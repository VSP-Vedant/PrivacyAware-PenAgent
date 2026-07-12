"""Project-wide settings for PrivacyAware-PenAgent.

Loads configuration from .env file and provides centralized
access to all project settings and constants.
Owner: Vighnesh (Member B) — shared foundation file.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env file (if present) before reading any environment variables.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

# ─── Paths ────────────────────────────────────────────────────────────────────

LOG_DIR: Path = PROJECT_ROOT / os.getenv("LOG_DIR", "logs")
RUNS_DIR: Path = PROJECT_ROOT / "runs"

# Ensure runtime directories exist.
LOG_DIR.mkdir(parents=True, exist_ok=True)
RUNS_DIR.mkdir(parents=True, exist_ok=True)

# ─── LLM — Cloud ──────────────────────────────────────────────────────────────

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
CLOUD_MODEL_PRIMARY: str = os.getenv("CLOUD_MODEL_PRIMARY", "gpt-4o")
CLOUD_MODEL_FALLBACK: str = os.getenv(
    "CLOUD_MODEL_FALLBACK", "claude-3-5-sonnet-20241022"
)

# ─── LLM — Local (Ollama) ─────────────────────────────────────────────────────

OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL_LOCAL: str = os.getenv(
    "OLLAMA_MODEL_LOCAL", "llama3:8b-instruct-q4_K_M"
)
OLLAMA_MODEL_FALLBACK: str = os.getenv(
    "OLLAMA_MODEL_FALLBACK", "mistral:7b-instruct-v0.3-q4_K_M"
)

# ─── Metasploit RPC ───────────────────────────────────────────────────────────

MSF_RPC_HOST: str = os.getenv("MSF_RPC_HOST", "127.0.0.1")
MSF_RPC_PORT: int = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_PASSWORD: str = os.getenv("MSF_RPC_PASSWORD", "")
MSF_RPC_SSL: bool = os.getenv("MSF_RPC_SSL", "false").lower() == "true"

# ─── LLM Router Thresholds ────────────────────────────────────────────────────

SENSITIVITY_THRESHOLD: float = float(os.getenv("SENSITIVITY_THRESHOLD", "0.6"))
COMPLEXITY_THRESHOLD: float = float(os.getenv("COMPLEXITY_THRESHOLD", "0.7"))

# ─── Safety / Budget ──────────────────────────────────────────────────────────

MAX_CLOUD_TOKENS_PER_RUN: int = int(os.getenv("MAX_CLOUD_TOKENS_PER_RUN", "50000"))
MAX_EXPLOIT_RETRIES: int = int(os.getenv("MAX_EXPLOIT_RETRIES", "3"))
MAX_TOTAL_STEPS: int = int(os.getenv("MAX_TOTAL_STEPS", "100"))
RUN_TIMEOUT_SECONDS: int = int(os.getenv("RUN_TIMEOUT_SECONDS", "1800"))

# ─── Allowed Target Ranges (SECURITY CRITICAL) ────────────────────────────────
# Every tool wrapper must validate targets against this list.
# Hardcoded here — never driven by environment to prevent override attacks.

ALLOWED_TARGET_RANGES: list[str] = [
    "10.10.0.0/16",       # HackTheBox VPN range (primary)
    "10.129.0.0/16",      # HackTheBox VPN range (alternate)
    "192.168.56.0/24",    # Local VirtualBox host-only
    "172.17.0.0/16",      # Docker containers
    "127.0.0.1/32",       # Localhost
]

# ─── Logging ──────────────────────────────────────────────────────────────────

LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

