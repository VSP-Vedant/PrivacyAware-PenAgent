"""LLM Client for API integration. Member A owned.

Handles actual execution of LLM calls based on RoutingDecision.
Supports OpenAI, Anthropic, and local Ollama.
"""

from __future__ import annotations

import json
import logging

import requests

from src.config.settings import ANTHROPIC_API_KEY, OLLAMA_HOST, OPENAI_API_KEY
from src.router.llm_router import RoutingDecision

logger = logging.getLogger(__name__)


class LLMClient:
    """Client for executing LLM prompts across different providers."""

    def __init__(self) -> None:
        """Docstring."""
        pass

    def generate(self, decision: RoutingDecision, prompt: str) -> str:
        """Generate a response using the routed model."""
        if decision.route == "CLOUD":
            if "gpt" in decision.model.lower():
                return self._call_openai(decision.model, prompt)
            else:
                return self._call_anthropic(decision.model, prompt)
        else:
            return self._call_ollama(decision.model, prompt)

    def _call_openai(self, model: str, prompt: str) -> str:
        """Call OpenAI Chat Completions API."""
        if not OPENAI_API_KEY:
            logger.warning("OPENAI_API_KEY not set. Returning mock response.")
            return self._mock_response()

        logger.info("Calling OpenAI API with model %s", model)
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }
        try:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30,
            )
            resp.raise_for_status()
            return str(resp.json()["choices"][0]["message"]["content"])
        except Exception as e:
            logger.error("OpenAI API call failed: %s", e)
            return self._mock_response()

    def _call_anthropic(self, model: str, prompt: str) -> str:
        """Call Anthropic Messages API."""
        if not ANTHROPIC_API_KEY:
            logger.warning("ANTHROPIC_API_KEY not set. Returning mock response.")
            return self._mock_response()

        logger.info("Calling Anthropic API with model %s", model)
        headers = {
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data = {
            "model": model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=data,
                timeout=30,
            )
            resp.raise_for_status()
            return str(resp.json()["content"][0]["text"])
        except Exception as e:
            logger.error("Anthropic API call failed: %s", e)
            return self._mock_response()

    def _call_ollama(self, model: str, prompt: str) -> str:
        """Call local Ollama API."""
        logger.info("Calling local Ollama with model %s", model)
        url = f"{OLLAMA_HOST}/api/generate"
        data = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        try:
            resp = requests.post(url, json=data, timeout=60)
            resp.raise_for_status()
            return str(resp.json()["response"])
        except Exception as e:
            logger.error("Ollama API call failed: %s", e)
            return self._mock_response()

    def _mock_response(self) -> str:
        """Return a mock JSON response for when APIs fail or keys are missing."""
        return json.dumps(
            {
                "recommendations": [
                    {
                        "module_path": "exploit/unix/ftp/vsftpd_234_backdoor",
                        "options": {"RPORT": 21},
                        "payload": "cmd/unix/interact",
                        "confidence": 0.9,
                        "reasoning": "Mocked LLM fallback response.",
                    }
                ]
            }
        )
