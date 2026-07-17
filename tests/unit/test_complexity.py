"""Unit tests for the Complexity Classifier.

This test suite verifies task-type complexity mappings.
"""

from __future__ import annotations

from src.router.complexity import TaskType, classify_complexity


def test_enum_complexity_mappings() -> None:
    """Test that TaskType enums return correct complexity scores."""
    assert classify_complexity(TaskType.SUMMARIZE) == 0.1
    assert classify_complexity(TaskType.FORMAT_OUTPUT) == 0.2
    assert classify_complexity(TaskType.COMMAND_TEMPLATE) == 0.3
    assert classify_complexity(TaskType.CVE_LOOKUP) == 0.5
    assert classify_complexity(TaskType.EXPLOIT_SELECTION) == 0.7
    assert classify_complexity(TaskType.PRIV_ESC_REASONING) == 0.9
    assert classify_complexity(TaskType.MULTI_CVE_CHAIN) == 1.0


def test_string_complexity_mappings() -> None:
    """Test that string representations map correctly to complexity scores."""
    assert classify_complexity("summarize") == 0.1
    assert classify_complexity("EXPLOIT_SELECTION") == 0.7
    assert classify_complexity("priv_esc_reasoning") == 0.9


def test_unknown_task_type() -> None:
    """Test that an unknown task type defaults to moderate complexity (0.5)."""
    assert classify_complexity("UNKNOWN_TASK") == 0.5
    assert classify_complexity("random_action_type") == 0.5
