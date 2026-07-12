import pytest

from src.utils.validators import TargetValidationError, validate_target


def test_validate_target_allowed() -> None:
    # Valid HackTheBox IP
    assert validate_target("10.10.11.230") is True
    # Localhost
    assert validate_target("127.0.0.1") is True


def test_validate_target_blocked() -> None:
    # Google DNS
    with pytest.raises(TargetValidationError):
        validate_target("8.8.8.8")

    # Random public IP
    with pytest.raises(TargetValidationError):
        validate_target("203.0.113.1")
