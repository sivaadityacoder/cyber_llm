#!/bin/bash

echo "🚀 Starting Cyber LLM RAG System..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install RAG dependencies
echo "📚 Installing RAG dependencies..."
pip install -r requirements_rag.txt

# Check if CVE database exists
if [ ! -f "data/detailed_cve_database.json" ]; then
    echo "⚠️  CVE database not found. Using existing data..."
fi

# Start RAG backend
echo "🔧 Starting RAG Backend on port 8000..."
cd Backend
python main.py &
BACKEND_PID=$!
cd ..

sleep 5

# Start RAG frontend
echo "🎨 Starting RAG Frontend on port 8502..."
cd Frontend  
streamlit run streamlit_app.py --server.port 8502 &
FRONTEND_PID=$!
cd ..

sleep 3

echo "✅ RAG System Ready!"
echo "🌐 Frontend: http://localhost:8502"
echo "🔧 Backend: http://localhost:8000"
echo "📖 API Docs: http://localhost:8000/docs"
echo ""
echo "🔍 To test RAG search, try:"
echo "curl \"http://localhost:8000/analyze-cve?cve_id=CVE-2024-0001\""
echo ""
echo "📝 For detailed guide, see: RAG_INTEGRATION_GUIDE.md"

# Save PIDs for cleanup
echo $BACKEND_PID > .backend.pid
echo $FRONTEND_PID > .frontend.pid

# Keep running
echo "Press Ctrl+C to stop all services..."
wait
