"""LLM Client for API integration. Member A owned.

Handles actual execution of LLM calls based on RoutingDecision.
Supports OpenAI, Anthropic, and local Ollama.

Task-aware local routing (Week 23+):
- ``generation`` tasks use Ollama ``format="json"`` for reliable structured output.
- ``synthesis`` tasks call Foundation-Sec-8B without JSON enforcement, with an
  automatic fallback to WhiteRabbitNeo if the model refuses/returns empty.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from src.config.settings import (
    ANTHROPIC_API_KEY,
    OLLAMA_HOST,
    OLLAMA_MODEL_LOCAL,
    OPENAI_API_KEY,
    load_model_config,
)
from src.router.llm_router import RoutingDecision

logger = logging.getLogger(__name__)

# ── Refusal detection for synthesis fallback ──────────────────────────────────
_REFUSAL_PHRASES = frozenset(
    {
        "i cannot assist",
        "i can't assist",
        "i'm unable to",
        "i am unable to",
        "as an ai",
        "i cannot help",
        "i can't help",
        "not able to provide",
        "against my guidelines",
        "i must decline",
    }
)


def _is_refusal(text: str) -> bool:
    """Return True if *text* looks like a model safety refusal."""
    lower = text.lower().strip()
    if not lower or lower in ("{}", "null", "none"):
        return True
    return any(phrase in lower for phrase in _REFUSAL_PHRASES)


class LLMClient:
    """Client for executing LLM prompts across different providers.

    Supports task-aware local model routing: when the ``RoutingDecision``
    includes a ``local_task_type``, the Ollama call adapts its parameters
    (model, JSON enforcement, timeout) accordingly.
    """

    def __init__(self) -> None:
        """Initialize LLMClient and load model config."""
        self._model_config = load_model_config()

    def generate(self, decision: RoutingDecision, prompt: str) -> str:
        """Generate a response using the routed model.

        When the route is CLOUD but no API key is configured, falls through
        to task-aware local routing so the correct Ollama model is used
        instead of the hardcoded legacy fallback.
        """
        if decision.route == "CLOUD":
            # ── No-key fast-path: fall through to task-aware local ─────
            if "gpt" in decision.model.lower() and not OPENAI_API_KEY:
                logger.warning(
                    "OPENAI_API_KEY not set — falling through to task-aware "
                    "local model instead of legacy fallback."
                )
                return self._call_ollama_task_aware(decision, prompt)
            if "gpt" not in decision.model.lower() and not ANTHROPIC_API_KEY:
                logger.warning(
                    "ANTHROPIC_API_KEY not set — falling through to task-aware "
                    "local model instead of legacy fallback."
                )
                return self._call_ollama_task_aware(decision, prompt)

            # ── Normal cloud dispatch (API keys present) ──────────────
            if "gpt" in decision.model.lower():
                return self._call_openai(decision.model, prompt, decision)
            else:
                return self._call_anthropic(decision.model, prompt, decision)
        else:
            return self._call_ollama_task_aware(decision, prompt)

    # ── Cloud providers ───────────────────────────────────────────────────────

    def _call_openai(
        self,
        model: str,
        prompt: str,
        decision: RoutingDecision | None = None,
    ) -> str:
        """Call OpenAI Chat Completions API.

        Falls back to task-aware local Ollama when the API call fails.
        """
        if not OPENAI_API_KEY:
            # Defensive guard — generate() should catch this first.
            logger.warning(
                "OPENAI_API_KEY not set — falling back to task-aware local model."
            )
            if decision:
                return self._call_ollama_task_aware(decision, prompt)
            return self._call_ollama(OLLAMA_MODEL_LOCAL, prompt, force_json=True)

        logger.info("Calling OpenAI API with model %s", model)
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        data: dict[str, Any] = {
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
            logger.error("OpenAI API call failed: %s — falling back to local", e)
            if decision:
                return self._call_ollama_task_aware(decision, prompt)
            return self._call_ollama(OLLAMA_MODEL_LOCAL, prompt, force_json=True)

    def _call_anthropic(
        self,
        model: str,
        prompt: str,
        decision: RoutingDecision | None = None,
    ) -> str:
        """Call Anthropic Messages API.

        Falls back to task-aware local Ollama when the API call fails.
        """
        if not ANTHROPIC_API_KEY:
            # Defensive guard — generate() should catch this first.
            logger.warning(
                "ANTHROPIC_API_KEY not set — falling back to task-aware local model."
            )
            if decision:
                return self._call_ollama_task_aware(decision, prompt)
            return self._call_ollama(OLLAMA_MODEL_LOCAL, prompt, force_json=True)

        logger.info("Calling Anthropic API with model %s", model)
        headers = {
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data: dict[str, Any] = {
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
            logger.error("Anthropic API call failed: %s — falling back to local", e)
            if decision:
                return self._call_ollama_task_aware(decision, prompt)
            return self._mock_response()

    # ── Task-aware local Ollama dispatch ───────────────────────────────────────

    def _call_ollama_task_aware(self, decision: RoutingDecision, prompt: str) -> str:
        """Dispatch to the correct Ollama model based on ``local_task_type``.

        * **generation** → Qwen2.5-Coder with ``format="json"``
        * **synthesis** → Foundation-Sec-8B (free-form), with automatic
          fallback to WhiteRabbitNeo if the response is a refusal/empty.
        * Unrecognised task types fall back to the legacy single-model path.

        IMPORTANT: always resolves the Ollama tag from the YAML config entry.
        ``decision.model`` may be a cloud model name (e.g. ``"gpt-4o"``) when
        this method is called as a no-key fallback from a CLOUD route — we must
        never pass that to Ollama.
        """
        task_type = decision.local_task_type or "synthesis"

        # ── Resolve actual Ollama model tag from config ───────────────────
        # Prefer config_entry on the decision (set by router for LOCAL routes).
        # For CLOUD→local fallbacks the entry is empty, so look up from YAML.
        # Ultimate safety net: OLLAMA_MODEL_LOCAL (never the cloud model name).
        config_entry = decision.model_config_entry or self._model_config.get(
            task_type, {}
        )
        ollama_tag = str(
            config_entry.get("ollama_tag")
            or self._model_config.get(task_type, {}).get("ollama_tag")
            or OLLAMA_MODEL_LOCAL
        )
        use_json = str(config_entry.get("format", "")).lower() == "json"
        timeout = int(str(config_entry.get("timeout", 90)))

        logger.info(
            "Task-aware Ollama dispatch",
            extra={
                "local_task_type": task_type,
                "model_used": ollama_tag,
                "original_decision_model": decision.model,
                "sensitivity_score": decision.sensitivity_score,
                "force_json": use_json,
                "timeout": timeout,
            },
        )

        # ── Generation path (JSON-enforced) ───────────────────────────────
        if task_type == "generation":
            return self._call_ollama(
                ollama_tag, prompt, force_json=True, timeout=timeout
            )

        # ── Synthesis path with fallback chain ────────────────────────────
        response = self._call_ollama(
            ollama_tag, prompt, force_json=False, timeout=timeout
        )

        if _is_refusal(response):
            # Try WhiteRabbitNeo fallback
            fallback_entry = self._model_config.get("synthesis_fallback", {})
            fallback_model = str(
                fallback_entry.get(
                    "ollama_tag", "monotykamary/whiterabbitneo-v1.5a:latest"
                )
            )
            fallback_timeout = int(str(fallback_entry.get("timeout", 90)))
            logger.warning(
                "Synthesis model refused/empty — retrying with fallback model %s",
                fallback_model,
            )
            response = self._call_ollama(
                fallback_model, prompt, force_json=False, timeout=fallback_timeout
            )

        return response

    # ── Core Ollama call ──────────────────────────────────────────────────────

    def _call_ollama(
        self,
        model: str,
        prompt: str,
        *,
        force_json: bool = True,
        timeout: int = 45,
    ) -> str:
        """Call local Ollama API.

        Args:
            model: Ollama model tag to invoke.
            prompt: The user prompt.
            force_json: When True, Ollama's ``format="json"`` is enabled and
                a strict JSON preamble is prepended to the prompt.
            timeout: Request timeout in seconds.
        """
        logger.info("Calling local Ollama with model %s (json=%s)", model, force_json)
        url = f"{OLLAMA_HOST}/api/generate"

        effective_prompt = prompt
        if force_json:
            # Prepend a strict JSON-only instruction so the model does not wrap
            # its answer in markdown prose or explanation text.
            json_prefix = (
                "IMPORTANT: You MUST respond with ONLY raw JSON. "
                "No markdown, no code fences, no explanation text. "
                "Start your response with { and end with }.\n\n"
            )
            effective_prompt = json_prefix + prompt

        data: dict[str, Any] = {
            "model": model,
            "prompt": effective_prompt,
            "stream": False,
        }
        if force_json:
            data["format"] = "json"  # Ollama native JSON mode (>=0.1.9)

        # Try requested model first, then legacy fallback model
        models_to_try = [(model, timeout)]
        if model != "llama3:8b":
            models_to_try.append(("llama3:8b", 60))

        for attempt_model, attempt_timeout in models_to_try:
            data["model"] = attempt_model
            try:
                resp = requests.post(url, json=data, timeout=attempt_timeout)
                resp.raise_for_status()
                raw = str(resp.json()["response"]).strip()
                # Strip any accidental markdown fences the model added
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
                return raw
            except Exception as e:
                logger.warning(
                    "Ollama call failed with model %s (timeout=%ds): %s",
                    attempt_model,
                    attempt_timeout,
                    e,
                )
                continue

        return self._mock_response()

    def _mock_response(
        self, target_ip: str = "", port: int = 0, service: str = ""
    ) -> str:
        """Return a safe fallback JSON response when all LLM APIs fail.

        The fallback is intentionally empty (no recommendations) so the
        exploit node falls through to SearchSploit discovery against the
        *actual* services in the attack graph rather than blindly trying
        a hardcoded module against a hardcoded IP.
        """
        logger.warning(
            "Using empty fallback response — no LLM available. "
            "ExploitAgent will rely on SearchSploit module discovery."
        )
        return json.dumps(
            {"recommendations": [], "fallback": "searchsploit", "query": service or ""}
        )
