<#
.SYNOPSIS
Setup script for Windows.

.DESCRIPTION
Creates a virtual environment and installs project dependencies.
#>

Write-Output "Setting up PrivacyAware-PenAgent virtual environment..."

if (-Not (Test-Path "venv")) {
    Write-Output "Creating virtual environment 'venv'..."
    python -m venv venv
} else {
    Write-Output "Virtual environment 'venv' already exists."
}

Write-Output "Activating virtual environment..."
& .\venv\Scripts\Activate.ps1

Write-Output "Upgrading pip..."
python -m pip install --upgrade pip

Write-Output "Installing project dependencies (including dev)..."
pip install -e .[dev]

Write-Output "Done! Run '.\venv\Scripts\Activate.ps1' to start working."
