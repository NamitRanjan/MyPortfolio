#!/bin/bash

# SOC Automation Dashboard - Quick Start Script

echo "================================================"
echo " SOC Automation Dashboard - Quick Start"
echo "================================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"

# Install dependencies
echo ""
echo "Installing dependencies..."
cd "$(dirname "$0")/backend"
pip install -q -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Start backend
echo ""
echo "Starting backend server..."
cd ..
export FLASK_APP=backend/app.py
python3 -m flask run --host 0.0.0.0 --port 5000 > /tmp/soc-dashboard.log 2>&1 &
BACKEND_PID=$!
echo "✓ Backend started (PID: $BACKEND_PID)"

# Wait for server to start
echo "Waiting for server to initialize..."
sleep 3

# Test connection
if curl -s http://localhost:5000/api/dashboard/stats > /dev/null; then
    echo "✓ Backend is responding"
else
    echo "❌ Backend is not responding"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

echo ""
echo "================================================"
echo " Dashboard is ready!"
echo "================================================"
echo ""
echo "Backend API: http://localhost:5000/api"
echo "Frontend:    Open frontend/index.html in your browser"
echo ""
echo "To stop the backend: kill $BACKEND_PID"
echo ""
echo "Quick API Tests:"
echo "  curl http://localhost:5000/api/dashboard/stats"
echo "  curl http://localhost:5000/api/alerts"
echo "  curl http://localhost:5000/api/threats"
echo ""
echo "Logs: tail -f /tmp/soc-dashboard.log"
echo "================================================"
