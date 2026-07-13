"""Tests for LLMClient. Member A."""

from unittest.mock import MagicMock, patch

import pytest

from src.router.llm_client import LLMClient
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

        # Test fallback when API key is None
        with patch("src.router.llm_client.OPENAI_API_KEY", ""):
            res = client.generate(decision, "test prompt")
            assert "Mocked LLM fallback response" in res


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

        # Test fallback when API key is None
        with patch("src.router.llm_client.ANTHROPIC_API_KEY", ""):
            res = client.generate(decision, "test prompt")
            assert "Mocked LLM fallback response" in res


def test_generate_local_ollama(client: LLMClient) -> None:
    decision = RoutingDecision(
        route="LOCAL",
        model="llama3",
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
