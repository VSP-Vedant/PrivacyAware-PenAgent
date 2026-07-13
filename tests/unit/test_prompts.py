"""Unit tests for prompt templates (Member A)."""

import pytest

from src.config.prompts import PROMPTS, get_prompt


def test_get_prompt_valid_template() -> None:
    prompt = get_prompt(
        "router_classification",
        task_input="Normal service summary",
        task_type="SUMMARIZE",
    )
    assert "ROUTING RULES" in prompt
    assert "sensitivity" in prompt


def test_get_prompt_invalid_template() -> None:
    with pytest.raises(ValueError):
        get_prompt("invalid_template")


def test_prompts_dictionary() -> None:
    assert len(PROMPTS) == 4
    assert "router_classification" in PROMPTS
    assert "exploit_selection" in PROMPTS
    assert "verification_post_mortem" in PROMPTS
    assert "recon_analysis" in PROMPTS


def test_exploit_selection_prompt_structure() -> None:
    prompt = get_prompt(
        "exploit_selection",
        service_info="vsftpd 2.3.4",
        cve_candidates="CVE-2011-2523",
        prior_failures=[],
    )
    assert "recommendations" in prompt
    assert "module_path" in prompt
    assert "confidence" in prompt
