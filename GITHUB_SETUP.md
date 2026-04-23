# GITHUB_SETUP.md — Mandatory Repository Configuration

> **Every rule here MUST be enforced via GitHub settings. Suggestions are not enough.**

---

## 1. Repository Structure

```
PrivacyAware-PenAgent/
├── .github/
│   ├── workflows/
│   │   ├── ci-lint.yml
│   │   ├── ci-test.yml
│   │   ├── ci-security.yml
│   │   └── ci-build.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── feature.yml
│   │   ├── bug.yml
│   │   └── research.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── src/
├── tests/
├── docs/
├── data/
├── scripts/
├── logs/                    # gitignored
├── reports/                 # gitignored
├── .env                     # gitignored
├── .gitignore
├── requirements.txt
├── requirements-dev.txt
└── pyproject.toml
```

---

## 2. Branch Strategy

### Protected Branches

| Branch | Protection Rules |
|--------|-----------------|
| `main` | Require PR, 2 approvals, CI must pass, no direct push, include administrators |
| `dev` | Require PR, 1 approval, CI must pass, no direct push |

### Branch Types

| Pattern | Purpose | Created From | Merges To |
|---------|---------|-------------|-----------|
| `main` | Stable releases (end of phase) | — | — |
| `dev` | Daily integration | `main` | `main` (phase end) |
| `feature/<issue>-<desc>` | New functionality | `dev` | `dev` |
| `bugfix/<issue>-<desc>` | Non-critical fixes | `dev` | `dev` |
| `hotfix/<issue>-<desc>` | Critical production fixes | `main` | `main` + `dev` |

### Branch Naming Examples

```
feature/12-nmap-xml-parser
feature/25-sensitivity-classifier
bugfix/34-msf-session-timeout
hotfix/41-credential-leak-fix
```

### Merge Rules

- Feature → dev: **Squash merge** (clean history)
- dev → main: **Merge commit** (preserve phase history)
- Hotfix → main: **Merge commit** (traceable fix)
- Delete branch after merge: **YES** (enforced)

---

## 3. GitHub Projects Board

### Board: "PrivacyAware-PenAgent Sprint Board"

| Column | Purpose | Automation |
|--------|---------|-----------|
| **Backlog** | All future work | New issues auto-added here |
| **Ready** | Scoped + estimated + assigned | Manual move after sprint planning |
| **In Progress** | Actively being worked on | Auto-move when branch created |
| **In Review** | PR submitted | Auto-move when PR opened |
| **Done** | Merged + verified | Auto-move when PR merged |

### Automation Rules (GitHub Projects v2)

```yaml
# Auto-add new issues to Backlog
trigger: issues.opened
action: add to project, set status = Backlog

# Auto-move to In Review when PR opened
trigger: pull_request.opened
action: set linked issue status = In Review

# Auto-move to Done when PR merged
trigger: pull_request.merged
action: set linked issue status = Done

# Auto-close issue when PR merged (via "Closes #N" in PR)
trigger: pull_request.merged
action: close linked issue
```

### Labels

| Label | Color | Purpose |
|-------|-------|---------|
| `phase-1` | `#0E8A16` | Phase 1 work |
| `phase-2` | `#1D76DB` | Phase 2 work |
| `phase-3` | `#5319E7` | Phase 3 work |
| `phase-4` | `#D93F0B` | Phase 4 work |
| `phase-5` | `#FBCA04` | Phase 5 work |
| `phase-6` | `#B60205` | Phase 6 work |
| `member-a` | `#C5DEF5` | Assigned to Member A |
| `member-b` | `#BFD4F2` | Assigned to Member B |
| `member-c` | `#D4C5F9` | Assigned to Member C |
| `member-d` | `#F9D0C4` | Assigned to Member D |
| `blocked` | `#E4E669` | Blocked by dependency |
| `critical` | `#B60205` | Must fix immediately |
| `security` | `#D93F0B` | Security-related |
| `research` | `#0075CA` | Research task |

---

## 4. Issue Templates

### Feature Request (`.github/ISSUE_TEMPLATE/feature.yml`)

```yaml
name: Feature Request
description: Propose new functionality
title: "[FEAT] "
labels: ["enhancement"]
body:
  - type: dropdown
    id: phase
    attributes:
      label: Phase
      options:
        - Phase 1 - Setup
        - Phase 2 - Core Agents
        - Phase 3 - Exploitation
        - Phase 4 - Integration
        - Phase 5 - Evaluation
        - Phase 6 - Paper
    validations:
      required: true
  - type: dropdown
    id: owner
    attributes:
      label: Primary Owner
      options:
        - Member A (LLM/AI)
        - Member B (Backend)
        - Member C (Security)
        - Member D (Data/State)
    validations:
      required: true
  - type: textarea
    id: description
    attributes:
      label: Description
      description: What should be built?
    validations:
      required: true
  - type: textarea
    id: acceptance
    attributes:
      label: Acceptance Criteria
      description: When is this done?
      value: |
        - [ ] Criterion 1
        - [ ] Criterion 2
    validations:
      required: true
  - type: dropdown
    id: estimate
    attributes:
      label: Time Estimate
      options:
        - "< 2 hours"
        - "2-4 hours"
        - "4-8 hours"
        - "1-2 days"
        - "3-5 days"
        - "> 1 week"
    validations:
      required: true
```

### Bug Report (`.github/ISSUE_TEMPLATE/bug.yml`)

```yaml
name: Bug Report
description: Report a defect
title: "[BUG] "
labels: ["bug"]
body:
  - type: dropdown
    id: severity
    attributes:
      label: Severity
      options:
        - Critical (blocks execution)
        - High (wrong results)
        - Medium (degraded performance)
        - Low (cosmetic/minor)
    validations:
      required: true
  - type: textarea
    id: description
    attributes:
      label: What happened?
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
    validations:
      required: true
  - type: textarea
    id: reproduce
    attributes:
      label: Steps to reproduce
      value: |
        1.
        2.
        3.
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Relevant logs
      render: shell
```

### Research Task (`.github/ISSUE_TEMPLATE/research.yml`)

```yaml
name: Research Task
description: Investigation or analysis work
title: "[RESEARCH] "
labels: ["research"]
body:
  - type: textarea
    id: question
    attributes:
      label: Research Question
    validations:
      required: true
  - type: textarea
    id: approach
    attributes:
      label: Approach
      description: How will you investigate?
    validations:
      required: true
  - type: textarea
    id: output
    attributes:
      label: Expected Output
      description: What artifact will this produce?
    validations:
      required: true
  - type: dropdown
    id: estimate
    attributes:
      label: Time Estimate
      options:
        - "< 2 hours"
        - "2-4 hours"
        - "4-8 hours"
        - "1-2 days"
    validations:
      required: true
```

---

## 5. PR Template (`.github/PULL_REQUEST_TEMPLATE.md`)

```markdown
## Description
<!-- What does this PR do? -->

## Related Issue
Closes #

## Type of Change
- [ ] Feature
- [ ] Bug fix
- [ ] Refactor
- [ ] Documentation
- [ ] Test
- [ ] CI/CD

## Module Owner Confirmation
- [ ] I own the files modified in this PR (per TEAM_ROLES.md)
- [ ] OR I have explicit approval from the owner (link comment)

## Checklist
- [ ] Code follows CLAUDE.md standards
- [ ] Type hints on all function signatures
- [ ] Docstrings on all public functions
- [ ] `black` formatting applied
- [ ] `flake8` passes
- [ ] Unit tests added/updated
- [ ] Coverage ≥70% for changed files
- [ ] No credentials in code
- [ ] No `print()` statements
- [ ] Logging follows standards

## Testing
<!-- How was this tested? -->

## Screenshots/Logs
<!-- If applicable -->
```

---

## 6. PR Rules (Enforced via Branch Protection)

| Rule | Setting |
|------|---------|
| Require PR for `main` | YES |
| Require PR for `dev` | YES |
| Required approvals for `main` | 2 |
| Required approvals for `dev` | 1 |
| Dismiss stale approvals | YES |
| Require status checks | ALL CI workflows must pass |
| Require branches up to date | YES |
| Include administrators | YES |
| Allow force push | NO |
| Allow deletions | NO |
| Require linear history | NO (merge commits allowed for dev→main) |

### Reviewer Assignment

| Author | Required Reviewer(s) |
|--------|---------------------|
| Member A | Member B + one of C/D |
| Member B | Member A + one of C/D |
| Member C | Member B + one of A/D |
| Member D | Member B + one of A/C |

Rule: **Author cannot approve their own PR. Member B reviews all integration-related PRs.**

---

## 7. .gitignore

```gitignore
# Environment
.env
.venv/
__pycache__/
*.pyc

# IDE
.vscode/
.idea/
*.swp

# Logs and reports
logs/
reports/
*.jsonl

# Data (large files)
data/raw/
*.db
*.sqlite

# OS
.DS_Store
Thumbs.db

# Testing
.coverage
htmlcov/
.pytest_cache/
.mypy_cache/

# Build
dist/
build/
*.egg-info/
```

---

*Configure ALL of these settings before any code is written. This is not optional.*
