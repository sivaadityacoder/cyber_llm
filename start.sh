#!/bin/bash

# Startup script for OwnLLM project
# This script starts both backend and frontend services

echo "🚀 Starting OwnLLM Project..."

# Change to project directory
cd /home/coder/startup/ownllm

# Kill any existing processes
echo "🔄 Stopping any existing services..."
pkill -f "python.*main_simple" || true
pkill -f "streamlit.*streamlit_app_simple" || true

# Wait a moment for processes to stop
sleep 2

# Activate virtual environment and start backend
echo "🔧 Starting backend service..."
source venv/bin/activate
python3 Backend/main_simple.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 3

# Test backend
echo "🔍 Testing backend connection..."
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Backend is running on http://localhost:8000"
else
    echo "❌ Backend failed to start"
    exit 1
fi

# Start frontend
echo "🎨 Starting frontend service..."
streamlit run Frontend/streamlit_app_simple.py --server.port 8501 --server.address 0.0.0.0 &
FRONTEND_PID=$!

# Wait for frontend to start
sleep 10

# Test frontend
echo "🔍 Testing frontend connection..."
if curl -s http://localhost:8501 > /dev/null; then
    echo "✅ Frontend is running on http://localhost:8501"
else
    echo "❌ Frontend failed to start"
fi

echo ""
echo "🎉 OwnLLM is now running!"
echo "📊 Backend API: http://localhost:8000"
echo "🌐 Frontend UI: http://localhost:8501"
echo ""
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "To stop the services, run: pkill -f 'python.*main_simple' && pkill -f 'streamlit.*streamlit_app_simple'"
