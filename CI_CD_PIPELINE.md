# CI_CD_PIPELINE.md — Critical Infrastructure

> **PR blocked if ANY check fails. No exceptions. No manual overrides.**

---

## Pipeline Overview

```
Push/PR → Lint → Type Check → Test → Security → Build → ✅ Merge allowed
                                                        ❌ Merge blocked
```

Four independent workflows run in parallel on every push to `dev` and every PR:

---

## 1. Code Validation (`ci-lint.yml`)

```yaml
# .github/workflows/ci-lint.yml
name: Code Validation

on:
  push:
    branches: [dev]
  pull_request:
    branches: [dev, main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          pip install -r requirements-dev.txt

      - name: Black formatting check
        run: |
          black --check --diff src/ tests/

      - name: Flake8 linting
        run: |
          flake8 src/ tests/ --max-line-length=88 --extend-ignore=E203,W503 --statistics

      - name: isort import sorting
        run: |
          isort --check-only --diff --profile black src/ tests/

      - name: mypy type checking
        run: |
          mypy src/ --ignore-missing-imports --strict

      - name: pydocstyle docstring check
        run: |
          pydocstyle src/ --convention=google --match='(?!test_).*\.py'
```

### Enforced Standards

| Tool | Config | Failure Condition |
|------|--------|-------------------|
| `black` | Line length 88 | Any file not formatted |
| `flake8` | Max 88, ignore E203/W503 | Any warning |
| `isort` | Profile: black | Any import misordered |
| `mypy` | `--strict` | Any type error |
| `pydocstyle` | Google convention | Missing docstring on public function |

---

## 2. Testing Pipeline (`ci-test.yml`)

```yaml
# .github/workflows/ci-test.yml
name: Testing Pipeline

on:
  push:
    branches: [dev]
  pull_request:
    branches: [dev, main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt

      - name: Run unit tests
        run: |
          pytest tests/unit/ -v --tb=short --junitxml=reports/unit-results.xml

      - name: Run integration tests (mock tools)
        run: |
          pytest tests/integration/ -v --tb=short -m "not requires_tools" --junitxml=reports/integration-results.xml

      - name: Coverage report
        run: |
          pytest tests/ --cov=src --cov-report=xml --cov-report=term-missing --cov-fail-under=70

      - name: Upload coverage
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage.xml

      - name: Upload test results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: test-results
          path: reports/
```

### Test Requirements

| Category | Location | Marker | Runs In CI |
|----------|----------|--------|-----------|
| Unit tests | `tests/unit/` | (default) | YES |
| Integration (mock) | `tests/integration/` | `not requires_tools` | YES |
| Integration (real) | `tests/integration/` | `requires_tools` | NO (local only) |
| End-to-end | `tests/e2e/` | `e2e` | NO (local only) |

### Coverage Rules

| Rule | Threshold |
|------|-----------|
| Overall project coverage | ≥70% |
| New files in PR | ≥70% (enforced via `--cov-fail-under`) |
| Coverage drop vs main | Not allowed (coverage cannot decrease) |

---

## 3. Security Checks (`ci-security.yml`)

```yaml
# .github/workflows/ci-security.yml
name: Security Checks

on:
  push:
    branches: [dev]
  pull_request:
    branches: [dev, main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Dependency vulnerability scan (pip-audit)
        run: |
          pip install pip-audit
          pip-audit --strict --desc

      - name: Secrets detection (trufflehog)
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified

      - name: Bandit security linting
        run: |
          pip install bandit
          bandit -r src/ -ll -ii --format json -o reports/bandit-report.json || true
          bandit -r src/ -ll -ii

      - name: Check for hardcoded IPs outside allowed ranges
        run: |
          # Fail if any hardcoded IPs found that aren't in allowed ranges
          python scripts/check_hardcoded_ips.py src/
```

### Security Rules

| Check | Tool | Failure Condition |
|-------|------|-------------------|
| Dependency vulns | `pip-audit` | Any known vulnerability |
| Secrets in code | `trufflehog` | Any verified secret detected |
| Python security | `bandit` | Any medium+ severity issue |
| Hardcoded IPs | Custom script | Any IP outside allowed ranges |

---

## 4. Build Validation (`ci-build.yml`)

```yaml
# .github/workflows/ci-build.yml
name: Build Validation

on:
  push:
    branches: [dev]
  pull_request:
    branches: [dev, main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Verify all modules import correctly
        run: |
          python -c "
          import importlib
          import pathlib
          errors = []
          for f in pathlib.Path('src').rglob('*.py'):
              if f.name == '__init__.py':
                  continue
              module = str(f).replace('/', '.').replace('\\\\', '.').removesuffix('.py')
              try:
                  importlib.import_module(module)
              except Exception as e:
                  errors.append(f'{module}: {e}')
          if errors:
              print('Import failures:')
              for e in errors:
                  print(f'  {e}')
              exit(1)
          print('All modules import successfully')
          "

      - name: Dry-run execution (help flag)
        run: |
          python -m src.main --help

      - name: Verify pyproject.toml
        run: |
          pip install build
          python -m build --sdist --no-isolation 2>&1 | tail -5
```

### Build Rules

| Check | Failure Condition |
|-------|-------------------|
| Module imports | Any module fails to import |
| CLI help | `--help` flag crashes |
| Package build | sdist build fails |

---

## 5. Required Status Checks

Configure in GitHub branch protection:

### For `dev` branch:
- `Code Validation / lint`
- `Testing Pipeline / test`
- `Security Checks / security`
- `Build Validation / build`

### For `main` branch:
- All of the above
- Manual approval from 2 reviewers

---

## 6. `requirements-dev.txt`

```
# Linting
black==24.4.2
flake8==7.1.0
isort==5.13.2
pydocstyle==6.3.0

# Type checking
mypy==1.10.0

# Testing
pytest==8.2.2
pytest-cov==5.0.0
pytest-asyncio==0.23.7
pytest-mock==3.14.0

# Security
bandit==1.7.9
pip-audit==2.7.3

# Build
build==1.2.1
```

---

## 7. `pyproject.toml` Configuration

```toml
[tool.black]
line-length = 88
target-version = ["py310"]

[tool.isort]
profile = "black"
line_length = 88

[tool.mypy]
python_version = "3.10"
strict = true
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "requires_tools: needs real tools (Nmap, MSF)",
    "e2e: end-to-end tests",
]
addopts = "-v --tb=short"

[tool.coverage.run]
source = ["src"]
omit = ["tests/*"]

[tool.coverage.report]
fail_under = 70
show_missing = true
```

---

*CI is the gatekeeper. If CI says no, the code does not merge. Period.*
