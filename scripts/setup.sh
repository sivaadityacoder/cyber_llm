#!/bin/bash

# Cyber LLM Setup Script
# This script sets up the development environment for the Cyber LLM project

set -e

echo "🔒 Cyber LLM - Ethical Hacking AI Assistant Setup"
echo "=================================================="

# Check if Python 3.11+ is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✅ Python version: $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📋 Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p {data/{models,vectorstore,knowledge_base,templates},logs,reports}

# Copy environment configuration
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment configuration..."
    cp .env.example .env
    echo "📝 Please edit .env file with your configuration"
fi

# Download sample models (optional)
echo "🤖 Setting up model directory..."
cat > data/models/README.md << 'EOF'
# LLM Models Directory

Place your GGUF format models in this directory for local inference.

## Recommended Models:
- **CodeLlama-7B-Instruct.gguf** - For code generation and analysis
- **Mistral-7B-Instruct-v0.2.gguf** - For general ethical hacking guidance
- **deepseek-coder-6.7b-instruct.gguf** - For advanced code analysis

## Download Sources:
- Hugging Face: https://huggingface.co/models
- Ollama: https://ollama.ai/library
- LM Studio: https://lmstudio.ai/

## Usage:
Update the `DEFAULT_MODEL` in your .env file to match your downloaded model filename.
EOF

# Initialize vector database
echo "🗄️ Initializing vector database..."
python3 -c "
from backend.rag.retrieval import RAGRetriever
retriever = RAGRetriever()
print('✅ Vector database initialized')
"

# Test backend startup
echo "🧪 Testing backend configuration..."
python3 -c "
from backend.config import settings
print(f'✅ Configuration loaded for {settings.environment} environment')
"

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Download LLM models to data/models/ directory"
echo "3. Start the backend: python -m uvicorn backend.main:app --reload"
echo "4. Start the frontend: streamlit run frontend/streamlit_app/app.py"
echo "5. Access the application at http://localhost:8501"
echo ""
echo "🔐 Default login credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "📚 Documentation: ./docs/"
echo "🐳 Docker: docker-compose up -d"