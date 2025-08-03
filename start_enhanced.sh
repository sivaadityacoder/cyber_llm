#!/bin/bash

# Enhanced OwnLLM Startup Script v3.0
# Starts the comprehensive ethical hacking and LLM security AI assistant

echo "🛡️ Starting Enhanced Ethical Hacking LLM v3.0..."
echo "🔒 Features: Cybersecurity + LLM Security + AI Safety"
echo "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "="

cd /home/coder/startup/ownllm

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Creating..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r Backend/requirements.txt
    pip install -r Frontend/requirements.txt
else
    echo "✅ Virtual environment found"
fi

# Kill any existing processes
echo "🧹 Cleaning up existing processes..."
pkill -f "main_enhanced" 2>/dev/null
pkill -f "streamlit.*enhanced" 2>/dev/null
sleep 2

# Start backend
echo "🚀 Starting Enhanced Backend (Port 8000)..."
source venv/bin/activate
python3 Backend/main_enhanced.py &
BACKEND_PID=$!

# Wait for backend to start
echo "⏳ Waiting for backend to initialize..."
sleep 5

# Check if backend is running
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Backend started successfully"
    
    # Get model info
    MODEL_INFO=$(curl -s http://localhost:8000/model/info | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'Model: {data[\"model_name\"]}')
print(f'Training Examples: {data[\"training_examples\"]}')
print(f'LLM Security Features: {len(data[\"llm_security_coverage\"])}')
" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "📊 $MODEL_INFO"
    fi
else
    echo "❌ Backend failed to start"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

# Start frontend
echo "🎨 Starting Enhanced Frontend (Port 8501)..."
streamlit run Frontend/streamlit_app_enhanced.py --server.port 8501 --server.address 0.0.0.0 &
FRONTEND_PID=$!

# Wait for frontend to start
echo "⏳ Waiting for frontend to initialize..."
sleep 8

# Check if frontend is running
if curl -s -I http://localhost:8501 > /dev/null; then
    echo "✅ Frontend started successfully"
else
    echo "❌ Frontend failed to start"
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 1
fi

echo ""
echo "🎉 Enhanced Ethical Hacking LLM v3.0 is now running!"
echo "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "="
echo "🌐 Frontend UI:      http://localhost:8501"
echo "🔌 Backend API:      http://localhost:8000"
echo "📚 API Documentation: http://localhost:8000/docs"
echo ""
echo "🛡️ Security Features Available:"
echo "  • Traditional Cybersecurity (Web, Network, System)"
echo "  • LLM Security (Prompt Injection, Jailbreaking)" 
echo "  • AI Safety (Secure Deployment, Testing)"
echo "  • 46 Comprehensive Training Examples"
echo "  • 12 Security Domain Coverage"
echo ""
echo "💡 Try asking about:"
echo "  • 'What is prompt injection and how to prevent it?'"
echo "  • 'Explain SQL injection attacks'"
echo "  • 'How do LLM jailbreaking techniques work?'"
echo ""
echo "🛑 To stop: ./stop.sh or Ctrl+C in terminals"
echo "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "="

# Save PIDs for stop script
echo $BACKEND_PID > .backend_pid
echo $FRONTEND_PID > .frontend_pid

# Wait for user interrupt
wait
