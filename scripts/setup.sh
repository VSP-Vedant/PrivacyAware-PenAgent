#!/bin/bash
# Setup script for Linux/macOS

echo "Setting up PrivacyAware-PenAgent virtual environment..."

if [ ! -d "venv" ]; then
    echo "Creating virtual environment 'venv'..."
    python3 -m venv venv
else
    echo "Virtual environment 'venv' already exists."
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing project dependencies (including dev)..."
pip install -e .[dev]

echo "Done! Run 'source venv/bin/activate' to start working."
