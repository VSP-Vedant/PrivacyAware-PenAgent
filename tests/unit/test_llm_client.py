"""Tests for LLMClient. Member A.

Includes task-aware local model routing tests for generation (JSON-enforced)
and synthesis (free-form with WhiteRabbitNeo fallback) paths.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.router.llm_client import LLMClient, _is_refusal
from src.router.llm_router import RoutingDecision


@pytest.fixture
def client() -> LLMClient:
    return LLMClient()


def test_generate_cloud_openai(client: LLMClient) -> None:
    decision = RoutingDecision(
        route="CLOUD",
        model="gpt-4",
        sensitivity=0.3,
        complexity=0.3,
        reasoning="test",
    )
    with patch("src.router.llm_client.requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "mock_response"}}]
        }
        mock_post.return_value = mock_resp

        # Test fallback when API key is None — new safe fallback returns empty recommendations
        with patch("src.router.llm_client.OPENAI_API_KEY", ""):
            res = client.generate(decision, "test prompt")
            import json as _json

            parsed = _json.loads(res)
            assert parsed["recommendations"] == []
            assert parsed["fallback"] == "searchsploit"


def test_generate_cloud_anthropic(client: LLMClient) -> None:
    decision = RoutingDecision(
        route="CLOUD",
        model="claude-3-opus",
        sensitivity=0.3,
        complexity=0.3,
        reasoning="test",
    )
    with patch("src.router.llm_client.requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"content": [{"text": "mock_response"}]}
        mock_post.return_value = mock_resp

        # Test fallback when API key is None — new safe fallback returns empty recommendations
        with patch("src.router.llm_client.ANTHROPIC_API_KEY", ""):
            res = client.generate(decision, "test prompt")
            import json as _json

            parsed = _json.loads(res)
            assert parsed["recommendations"] == []
            assert parsed["fallback"] == "searchsploit"


def test_generate_local_ollama_generation(client: LLMClient) -> None:
    """Generation task type should call Ollama with format='json'."""
    decision = RoutingDecision(
        route="LOCAL",
        model="qwen2.5-coder:14b",
        sensitivity=0.3,
        complexity=0.3,
        reasoning="test",
        local_task_type="generation",
        model_config_entry={
            "name": "Qwen2.5-Coder-14B",
            "ollama_tag": "qwen2.5-coder:14b",
            "format": "json",
            "timeout": 120,
        },
    )
    with patch("src.router.llm_client.requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": '{"recommendations": []}'}
        mock_post.return_value = mock_resp

        res = client.generate(decision, "test prompt")
        assert "recommendations" in res

        # Verify that format="json" was sent to Ollama
        call_args = mock_post.call_args
        sent_data = call_args.kwargs.get("json") or call_args[1].get("json")
        assert sent_data["format"] == "json"


def test_generate_local_ollama_synthesis(client: LLMClient) -> None:
    """Synthesis task type should call Ollama WITHOUT format='json'."""
    decision = RoutingDecision(
        route="LOCAL",
        model="hf.co/QuantFactory/Foundation-Sec-8B-GGUF:Q4_K_M",
        sensitivity=0.3,
        complexity=0.3,
        reasoning="test",
        local_task_type="synthesis",
        model_config_entry={
            "name": "Foundation-Sec-8B-Instruct",
            "ollama_tag": "hf.co/QuantFactory/Foundation-Sec-8B-GGUF:Q4_K_M",
            "format": None,
            "timeout": 90,
        },
    )
    with patch("src.router.llm_client.requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "response": "The service is vulnerable to CVE-2021-3156"
        }
        mock_post.return_value = mock_resp

        res = client.generate(decision, "test prompt")
        assert "CVE-2021-3156" in res

        # Verify that format="json" was NOT sent for synthesis
        call_args = mock_post.call_args
        sent_data = call_args.kwargs.get("json") or call_args[1].get("json")
        assert "format" not in sent_data


def test_synthesis_fallback_to_whiterabbitneo(client: LLMClient) -> None:
    """If synthesis model refuses, should retry with WhiteRabbitNeo."""
    decision = RoutingDecision(
        route="LOCAL",
        model="hf.co/QuantFactory/Foundation-Sec-8B-GGUF:Q4_K_M",
        sensitivity=0.3,
        complexity=0.3,
        reasoning="test",
        local_task_type="synthesis",
        model_config_entry={
            "name": "Foundation-Sec-8B-Instruct",
            "ollama_tag": "hf.co/QuantFactory/Foundation-Sec-8B-GGUF:Q4_K_M",
            "format": None,
            "timeout": 90,
        },
    )

    # First call returns a refusal, second call (fallback) returns useful output
    mock_resp_refusal = MagicMock()
    mock_resp_refusal.json.return_value = {
        "response": "I cannot assist with offensive security tasks."
    }

    mock_resp_fallback = MagicMock()
    mock_resp_fallback.json.return_value = {
        "response": "The target is vulnerable to buffer overflow via CVE-2021-44228"
    }

    with patch("src.router.llm_client.requests.post") as mock_post:
        mock_post.side_effect = [mock_resp_refusal, mock_resp_fallback]
        res = client.generate(decision, "analyze this service")

        assert "CVE-2021-44228" in res
        # Should have been called twice: once for Foundation-Sec, once for WhiteRabbitNeo
        assert mock_post.call_count == 2


def test_generate_local_ollama_legacy(client: LLMClient) -> None:
    """Legacy test: LOCAL without local_task_type still works."""
    decision = RoutingDecision(
        route="LOCAL",
        model="llama3:8b",
        sensitivity=0.3,
        complexity=0.3,
        reasoning="test",
    )
    with patch("src.router.llm_client.requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "local_mock_response"}
        mock_post.return_value = mock_resp

        res = client.generate(decision, "test prompt")
        assert res == "local_mock_response"


def test_is_refusal_detects_known_phrases() -> None:
    """Test _is_refusal detects various refusal patterns."""
    assert _is_refusal("I cannot assist with that request.")
    assert _is_refusal("As an AI, I must decline this.")
    assert _is_refusal("")
    assert _is_refusal("{}")
    assert _is_refusal("null")
    assert not _is_refusal("The service runs vsftpd 2.3.4 which is vulnerable.")
    assert not _is_refusal('{"recommendations": []}')


def test_cloud_route_no_key_uses_task_aware_model_not_cloud_name(
    client: LLMClient,
) -> None:
    """Regression: when CLOUD route has no API key, Ollama must be called with
    the task-aware model tag (qwen2.5-coder:14b), never with 'gpt-4o'.

    This was the root bug: decision.model='gpt-4o' was passed directly to
    _call_ollama(), causing a Connection refused error against the Ollama API.
    """
    # Simulate the router returning a CLOUD decision (no local_task_type set,
    # no model_config_entry) — exactly what happens at runtime.
    decision = RoutingDecision(
        route="CLOUD",
        model="gpt-4o",
        sensitivity=1.0,
        complexity=1.0,
        reasoning="Cloud route: complexity >= threshold",
        local_task_type="generation",   # orchestrator always sets this
        model_config_entry={},          # empty — as it is for CLOUD decisions
    )

    with patch("src.router.llm_client.OPENAI_API_KEY", ""):
        with patch("src.router.llm_client.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"response": '{"recommendations": []}'}
            mock_post.return_value = mock_resp

            client.generate(decision, "test prompt")

            # The model sent to Ollama must NOT be 'gpt-4o'
            call_args = mock_post.call_args
            sent_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert sent_data["model"] != "gpt-4o", (
                "Bug: cloud model name was passed to Ollama — "
                f"got {sent_data['model']!r}, expected qwen2.5-coder:14b"
            )
            assert sent_data["model"] == "qwen2.5-coder:14b"
            assert sent_data.get("format") == "json"   # generation task → JSON mode
