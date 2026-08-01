.PHONY: setup test lint format

setup:
	@echo "Setting up environment..."
	@bash scripts/setup.sh

test:
	pytest tests/ --cov=src --cov-report=term-missing

lint:
	flake8 src/ tests/
	mypy --strict src/

format:
	isort src/ tests/
	black src/ tests/
