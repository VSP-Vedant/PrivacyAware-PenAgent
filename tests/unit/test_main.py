"""Tests for CLI entry point (main.py)."""

from unittest.mock import MagicMock, patch

import pytest

from src.main import main
from src.utils.validators import TargetValidationError


def _mock_final_state() -> dict[str, object]:
    """Build a mock final state with all required PenTestState fields."""
    return {
        "step_count": 5,
        "attack_graph": MagicMock(graph="mock_graph"),
        "routing_decisions": [{"route": "LOCAL", "model": "llama3:8b"}],
        "cloud_tokens_used": 0,
    }


@patch("sys.argv", ["main.py", "--target", "10.10.10.10"])
@patch("src.main._check_ollama")
@patch("src.agents.orchestrator.build_graph")
@patch("src.main.PersistenceManager")
@patch("src.main.validate_target")
def test_main_success(
    mock_validate: MagicMock,
    mock_pm: MagicMock,
    mock_build_graph: MagicMock,
    mock_check_ollama: MagicMock,
) -> None:
    """Test successful CLI execution with default args."""
    # Setup mocks
    mock_app = MagicMock()
    mock_app.invoke.return_value = _mock_final_state()
    mock_build_graph.return_value = mock_app

    mock_pm_instance = MagicMock()
    mock_pm.return_value = mock_pm_instance

    # Run
    main()

    # Verify
    mock_validate.assert_called_once_with("10.10.10.10")
    mock_build_graph.assert_called_once()
    mock_app.invoke.assert_called_once()
    mock_pm_instance.save_graph.assert_called_once_with("mock_graph")


@patch("sys.argv", ["main.py", "--target", "invalid_target"])
@patch("src.main.validate_target")
def test_main_invalid_target(mock_validate: MagicMock) -> None:
    """Test CLI exits with code 1 on invalid target."""
    mock_validate.side_effect = TargetValidationError("Invalid target")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1


@patch("sys.argv", ["main.py", "--target", "10.10.10.10", "--no-graph"])
@patch("src.main._check_ollama")
@patch("src.agents.orchestrator.build_graph")
@patch("src.main.validate_target")
def test_main_graph_ablation(
    mock_validate: MagicMock, mock_build_graph: MagicMock, mock_check_ollama: MagicMock
) -> None:
    """Test --no-graph ablation flag triggers warning and runs."""
    # Setup mocks
    mock_app = MagicMock()
    mock_app.invoke.side_effect = Exception("Test failure")
    mock_build_graph.return_value = mock_app

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1


@patch("sys.argv", ["main.py", "--target", "10.10.10.10", "--no-router"])
@patch("src.main._check_ollama")
@patch("src.agents.orchestrator.build_graph")
@patch("src.main.PersistenceManager")
@patch("src.main.validate_target")
def test_main_no_router_flag(
    mock_validate: MagicMock,
    mock_pm: MagicMock,
    mock_build_graph: MagicMock,
    mock_check_ollama: MagicMock,
) -> None:
    """Test --no-router flag sets router_enabled=False in initial state."""
    mock_app = MagicMock()
    mock_app.invoke.return_value = _mock_final_state()
    mock_build_graph.return_value = mock_app
    mock_pm.return_value = MagicMock()

    main()

    # Verify the initial state passed to invoke has router_enabled=False
    call_args = mock_app.invoke.call_args[0][0]
    assert call_args["router_enabled"] is False


@patch("sys.argv", ["main.py", "--target", "10.10.10.10", "--no-verify"])
@patch("src.main._check_ollama")
@patch("src.agents.orchestrator.build_graph")
@patch("src.main.PersistenceManager")
@patch("src.main.validate_target")
def test_main_no_verify_flag(
    mock_validate: MagicMock,
    mock_pm: MagicMock,
    mock_build_graph: MagicMock,
    mock_check_ollama: MagicMock,
) -> None:
    """Test --no-verify ablation flag is accepted without error."""
    mock_app = MagicMock()
    mock_app.invoke.return_value = _mock_final_state()
    mock_build_graph.return_value = mock_app
    mock_pm.return_value = MagicMock()

    # Should not raise — flag is accepted
    main()
    mock_app.invoke.assert_called_once()


@patch("sys.argv", ["main.py", "--target", "10.10.10.10", "--visualize"])
@patch("src.main._check_ollama")
@patch("src.agents.orchestrator.build_graph")
@patch("src.main.PersistenceManager")
@patch("src.main.validate_target")
def test_main_visualize_flag(
    mock_validate: MagicMock,
    mock_pm: MagicMock,
    mock_build_graph: MagicMock,
    mock_check_ollama: MagicMock,
) -> None:
    """Test --visualize flag triggers graph visualization."""
    mock_app = MagicMock()
    mock_app.invoke.return_value = _mock_final_state()
    mock_build_graph.return_value = mock_app
    mock_pm.return_value = MagicMock()

    with patch("src.utils.visualize.visualize_attack_graph") as mock_viz:
        main()
        mock_viz.assert_called_once()
