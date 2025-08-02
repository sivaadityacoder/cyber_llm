#!/bin/bash

# Cyber LLM Startup Script
# Starts the backend API and frontend application

set -e

echo "🔒 Starting Cyber LLM - Ethical Hacking AI Assistant"
echo "==================================================="

# Function to check if port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "❌ Port $port is already in use"
        return 1
    fi
    return 0
}

# Function to start backend
start_backend() {
    echo "🚀 Starting backend API server..."
    if check_port 8000; then
        python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload &
        BACKEND_PID=$!
        echo "✅ Backend started with PID: $BACKEND_PID"
    else
        echo "⚠️ Backend may already be running on port 8000"
    fi
}

# Function to start frontend
start_frontend() {
    echo "🎨 Starting frontend application..."
    if check_port 8501; then
        streamlit run frontend/streamlit_app/app.py --server.port 8501 --server.address 0.0.0.0 &
        FRONTEND_PID=$!
        echo "✅ Frontend started with PID: $FRONTEND_PID"
    else
        echo "⚠️ Frontend may already be running on port 8501"
    fi
}

# Function to start Redis (if available)
start_redis() {
    if command -v redis-server &> /dev/null; then
        if check_port 6379; then
            echo "🗄️ Starting Redis server..."
            redis-server --daemonize yes --port 6379
            echo "✅ Redis started on port 6379"
        else
            echo "⚠️ Redis may already be running on port 6379"
        fi
    else
        echo "⚠️ Redis not found - using in-memory caching"
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo "✅ Backend stopped"
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
        echo "✅ Frontend stopped"
    fi
    echo "👋 Goodbye!"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Activate virtual environment if available
if [ -d "venv" ]; then
    echo "🔄 Activating virtual environment..."
    source venv/bin/activate
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️ .env file not found. Using default configuration."
    echo "💡 Run './scripts/setup.sh' to create configuration file."
fi

# Start services
start_redis
sleep 2
start_backend
sleep 5
start_frontend

echo ""
echo "🎉 All services started successfully!"
echo ""
echo "🌐 Access points:"
echo "   Frontend (Streamlit): http://localhost:8501"
echo "   Backend API: http://localhost:8000"
echo "   API Documentation: http://localhost:8000/docs"
echo ""
echo "🔐 Default login credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for services
wait