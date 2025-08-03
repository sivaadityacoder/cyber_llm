#!/bin/bash

# Startup script for Ethical Hacking LLM Project
echo "🛡️ Starting Ethical Hacking LLM Assistant..."

# Change to project directory
cd /home/coder/startup/ownllm

# Kill any existing processes
echo "🔄 Stopping any existing services..."
pkill -f "python.*main_ethical" || true
pkill -f "streamlit.*streamlit_app_ethical" || true
sleep 2

# Activate virtual environment and start backend
echo "🔧 Starting ethical hacking backend..."
source venv/bin/activate
python3 Backend/main_ethical.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 3

# Test backend
echo "🔍 Testing backend connection..."
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Ethical Hacking Backend is running on http://localhost:8000"
    
    # Get model info
    MODEL_INFO=$(curl -s http://localhost:8000/model/info | python3 -c "import sys, json; data=json.load(sys.stdin); print(f'Model: {data[\"model_name\"]} | Status: {data[\"status\"]} | Examples: {data[\"training_examples\"]}')")
    echo "🤖 $MODEL_INFO"
else
    echo "❌ Backend failed to start"
    exit 1
fi

# Start frontend
echo "🎨 Starting ethical hacking frontend..."
streamlit run Frontend/streamlit_app_ethical.py --server.port 8501 --server.address 0.0.0.0 &
FRONTEND_PID=$!

# Wait for frontend to start
sleep 10

# Test frontend
echo "🔍 Testing frontend connection..."
if curl -s http://localhost:8501 > /dev/null; then
    echo "✅ Ethical Hacking Frontend is running on http://localhost:8501"
else
    echo "❌ Frontend failed to start"
fi

echo ""
echo "🎉 Ethical Hacking LLM Assistant is now running!"
echo "🛡️ Specialized in: Web Security, Network Security, Incident Response, Digital Forensics"
echo "📊 Backend API: http://localhost:8000"
echo "🌐 Frontend UI: http://localhost:8501"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "To stop: pkill -f 'python.*main_ethical' && pkill -f 'streamlit.*streamlit_app_ethical'"
