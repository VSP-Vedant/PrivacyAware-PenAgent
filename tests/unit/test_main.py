"""Tests for CLI entry point (main.py)."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from src.main import main
from src.utils.validators import TargetValidationError


@patch("sys.argv", ["main.py", "--target", "10.10.10.10"])
@patch("src.main.build_graph")
@patch("src.main.PersistenceManager")
@patch("src.main.validate_target")
def test_main_success(
    mock_validate: MagicMock, mock_pm: MagicMock, mock_build_graph: MagicMock
) -> None:
    # Setup mocks
    mock_app = MagicMock()
    mock_app.invoke.return_value = {
        "step_count": 5,
        "attack_graph": MagicMock(graph="mock_graph"),
    }
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
    mock_validate.side_effect = TargetValidationError("Invalid target")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1


@patch("sys.argv", ["main.py", "--target", "10.10.10.10", "--no-graph"])
@patch("src.main.build_graph")
@patch("src.main.validate_target")
def test_main_graph_ablation(
    mock_validate: MagicMock, mock_build_graph: MagicMock
) -> None:
    # Setup mocks
    mock_app = MagicMock()
    mock_app.invoke.side_effect = Exception("Test failure")
    mock_build_graph.return_value = mock_app

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
