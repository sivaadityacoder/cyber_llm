#!/bin/bash

# Stop script for Enhanced OwnLLM project v3.0

echo "🛑 Stopping Enhanced OwnLLM services..."

# Kill enhanced version processes
pkill -f "main_enhanced" || true
pkill -f "streamlit.*enhanced" || true

# Kill legacy version processes (if any)
pkill -f "python.*main_simple" || true
pkill -f "streamlit.*streamlit_app_simple" || true

# Kill by PID if available
if [ -f ".backend_pid" ]; then
    kill $(cat .backend_pid) 2>/dev/null || true
    rm .backend_pid
fi

if [ -f ".frontend_pid" ]; then
    kill $(cat .frontend_pid) 2>/dev/null || true
    rm .frontend_pid
fi

# Wait for processes to stop
sleep 3

echo "✅ All Enhanced OwnLLM services stopped."
