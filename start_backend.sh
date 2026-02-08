#!/bin/bash

echo "Starting Data Whisperer Backend..."
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if requirements are installed
if ! python3 -c "import fastapi" &> /dev/null; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
    echo ""
    echo "Installing Playwright browsers..."
    playwright install chromium
    echo ""
fi

# Start the backend server
echo "Starting FastAPI server on http://localhost:8000"
echo "Press Ctrl+C to stop"
echo ""
python3 backend.py
