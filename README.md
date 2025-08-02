# 🔒 Cyber LLM - Ethical Hacking AI Assistant

A comprehensive self-hosted AI assistant specifically designed for ethical hacking, bug bounty hunting, and cybersecurity research. This system combines a local uncensored LLM with RAG capabilities, voice interaction, and integrated security tools.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)

## ✨ Features

### 🧠 **Local LLM Integration**
- Support for uncensored open-source models (LLaMA, Mistral, DeepSeek Coder)
- GGUF format model loading with GPU/CPU optimization
- Specialized ethical hacking knowledge and guidance
- Vulnerability analysis and CVE correlation

### 🔎 **RAG Pipeline System**
- ChromaDB/FAISS vector database integration
- Comprehensive cybersecurity knowledge base
- Real-time document retrieval for enhanced responses
- OWASP guidelines, CVE feeds, and payload databases

### ⚙️ **Security Tools Integration**
- **Nmap** for network reconnaissance and port scanning
- **Nuclei** for automated vulnerability scanning
- **Payload Generator** for security testing
- **Report Generation** in multiple formats (PDF, HTML, Markdown)

### 💬 **Modern Web Interface**
- ChatGPT-style conversational UI
- Real-time chat with streaming responses
- Dark/light mode toggle
- Code syntax highlighting
- File upload/download capabilities

### 🎙️ **Voice Assistant**
- Speech-to-text using speech_recognition
- Text-to-speech with natural voice responses
- Wake-word detection ("Hey Cyber")
- Voice command processing

### 🔒 **Security & Compliance**
- JWT-based authentication
- Rate limiting and abuse prevention
- Comprehensive audit logging
- Ethical guidelines enforcement

## 🚀 Quick Start

### Option 1: Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/sivaadityacoder/cyber_llm.git
cd cyber_llm

# Deploy with Docker
./scripts/deploy.sh

# Access the application
# Frontend: http://localhost:8501
# Backend API: http://localhost:8000/docs
```

### Option 2: Manual Setup

```bash
# Clone and setup
git clone https://github.com/sivaadityacoder/cyber_llm.git
cd cyber_llm

# Run setup script
./scripts/setup.sh

# Start services
./scripts/start.sh
```

### Option 3: Development Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env

# Start backend
python -m uvicorn backend.main:app --reload

# Start frontend (in another terminal)
streamlit run frontend/streamlit_app/app.py
```

## 📋 Default Credentials

- **Username**: `admin`
- **Password**: `admin123`

> ⚠️ **Important**: Change these credentials in production!

## 🏗️ Architecture

```
cyber_llm/
├── backend/                 # FastAPI backend application
│   ├── api/                # API endpoints and middleware
│   ├── llm/                # LLM integration and management
│   ├── rag/                # RAG pipeline and retrieval
│   ├── tools/              # Security tools integration
│   └── voice/              # Voice processing components
├── frontend/               # Streamlit web application
├── data/                   # Data storage and models
├── docker/                 # Docker configuration
├── scripts/                # Deployment and utility scripts
└── docs/                   # Documentation
```

## 🔧 Configuration

### Environment Variables

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# LLM Configuration
LLM_MODEL_PATH=./models/
DEFAULT_MODEL=llama-2-7b-chat.gguf
MAX_TOKENS=2048
TEMPERATURE=0.7

# Security Configuration
JWT_SECRET_KEY=your-secret-key
RATE_LIMIT_PER_MINUTE=60
SESSION_TIMEOUT=3600

# Voice Configuration
VOICE_ENABLED=true
VOICE_RATE=150
VOICE_VOLUME=0.9
```

### Model Setup

1. Download GGUF models to `data/models/` directory
2. Update `DEFAULT_MODEL` in `.env` file
3. Recommended models:
   - **CodeLlama-7B-Instruct.gguf** - Code generation
   - **Mistral-7B-Instruct-v0.2.gguf** - General guidance
   - **deepseek-coder-6.7b-instruct.gguf** - Advanced analysis

## 🛠️ Usage Examples

### Chat Interface
```
User: "How do I test for XSS vulnerabilities?"
AI: "Cross-Site Scripting (XSS) testing involves injecting scripts into web applications..."
```

### Security Scanning
```bash
# Nmap scan via API
curl -X POST "http://localhost:8000/api/v1/tools/scan/nmap" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool": "nmap", "target": "example.com", "options": {"scan_type": "syn"}}'
```

### Payload Generation
```python
# Generate XSS payloads
response = requests.post(
    "http://localhost:8000/api/v1/tools/payloads/generate",
    params={"payload_type": "xss", "target_language": "python"}
)
```

## 📚 API Documentation

The full API documentation is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Main Endpoints

- **Authentication**: `/api/v1/auth/`
- **Chat Interface**: `/api/v1/chat/`
- **Security Tools**: `/api/v1/tools/`
- **Voice Processing**: `/api/v1/voice/`

## 🛡️ Ethical Guidelines

This tool is designed for **legitimate security research and authorized testing only**:

✅ **Authorized Use Cases**:
- Penetration testing on systems you own
- Bug bounty programs with proper scope
- Educational cybersecurity research
- Security assessments with written permission

❌ **Prohibited Uses**:
- Unauthorized system access
- Malicious hacking activities
- Testing without proper authorization
- Any illegal cybersecurity activities

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [./docs/](./docs/)
- **Issues**: [GitHub Issues](https://github.com/sivaadityacoder/cyber_llm/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sivaadityacoder/cyber_llm/discussions)

## 🙏 Acknowledgments

- **OWASP** for cybersecurity guidelines
- **Nuclei** for vulnerability templates
- **HackerOne** for bug bounty insights
- **Open Source Community** for tools and libraries

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.