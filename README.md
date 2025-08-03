#  Cyber LLM - Advanced Cybersecurity AI Assistant

A comprehensive cybersecurity AI platform that combines live CVE analysis, intelligent threat assessment, and LLM-powered security insights with real-time vulnerability data and advanced error handling.

##  Features

- ** Live CVE Analysis**: Real-time vulnerability data from NVD API with CVSS scoring
- ** AI-Powered Security Assistant**: Intelligent responses using advanced LLM models
- ** Risk Assessment**: CVSS score analysis and threat prioritization
- ** Offline Mode**: Comprehensive fallback analysis when API services are unavailable
- ** Interactive Chat Interface**: User-friendly Streamlit frontend with error handling
- ** Comprehensive Training Data**: 46+ cybersecurity scenarios covering 12 security domains
- ** Enhanced Error Recovery**: Robust error handling and graceful degradation
- ** Secure API Management**: Environment variable support and secure key handling

## Quick Start

### Start the Enhanced Project:
```bash
./start_enhanced.sh
```

### Stop the project:
```bash
./stop.sh
```

## Manual Start (Enhanced Version)

### 1. Start Enhanced Backend
```bash
cd /home/coder/startup/ownllm
source venv/bin/activate
python3 Backend/main_enhanced.py
```

### 2. Start Enhanced Frontend (in a new terminal)
```bash
cd /home/coder/startup/ownllm
source venv/bin/activate
streamlit run Frontend/streamlit_app_enhanced.py --server.port 8501 --server.address 0.0.0.0
```

## Legacy Manual Start (Basic Version)

### 1. Start Basic Backend
```bash
cd /home/coder/startup/ownllm
source venv/bin/activate
python3 Backend/main_simple.py
```

### 2. Start Basic Frontend (in a new terminal)
```bash
cd /home/coder/startup/ownllm
source venv/bin/activate
streamlit run Frontend/streamlit_app_simple.py --server.port 8501 --server.address 0.0.0.0
```

## Access Points

- **Frontend UI**: http://localhost:8501
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## Features

### Enhanced Features v3.0
-  **Comprehensive Cybersecurity Knowledge**: Traditional security + LLM security
-  **46 Training Examples**: Web App, Network, System, Crypto, Forensics, LLM Security
-  **LLM Attack Vectors**: Prompt injection, jailbreaking, context poisoning, DoS
-  **AI Safety Expertise**: Secure deployment, testing, validation, ethics
-  **Real-world Examples**: Based on LLM Hacking Database research
-  **Advanced UI**: Tabbed interface, analytics, confidence scoring
-  **REST API**: Comprehensive endpoints for all security domains

### Core Features
-  FastAPI backend with comprehensive security knowledge
-  Streamlit frontend with enhanced chat interface  
-  Backend status monitoring and health checks
-  Chat history management and export
-  Confidence scoring for AI responses
-  Multiple security domain coverage

### Security Domains Covered
1. **Web Application Security** (SQLi, XSS, CSRF, XXE, SSRF, etc.)
2. **Network Security** (MITM, Port Scanning, DDoS, Wireless)
3. **System Security** (Privilege Escalation, Buffer Overflows)
4. **Cryptography** (Encryption, Hashing, Digital Signatures)
5. **Incident Response** (Detection, Containment, Recovery)
6. **Digital Forensics** (Evidence Collection, Analysis)
7. **Social Engineering Defense** (Awareness, Controls)
8. **Legal and Ethical Guidelines** (Compliance, Ethics)
9. ** LLM Security** (Prompt Injection, Jailbreaking)
10. ** AI Safety** (Secure Deployment, Testing)
11. ** Prompt Engineering Security** (Context Protection)
12. ** AI Infrastructure Security** (Access Control)

## File Structure

```
├── Backend/
│   ├── main_simple.py          # Simplified backend
│   ├── main.py                 # Full-featured backend (WIP)
│   ├── requirements.txt        # Full dependencies
│   └── requirements_minimal.txt # Basic dependencies
├── Frontend/
│   ├── streamlit_app_simple.py # Simplified frontend
│   ├── streamlit_app.py        # Full-featured frontend (WIP)
│   ├── requirements.txt        # Full dependencies
│   └── requirements_minimal.txt # Basic dependencies
├── data/                       # Data files
├── model/                      # Model files
├── venv/                       # Python virtual environment
├── start.sh                    # Startup script
├── stop.sh                     # Stop script
└── README.md                   # This file
```

## Development

### Install Dependencies
```bash
source venv/bin/activate
pip install -r Backend/requirements_minimal.txt
pip install -r Frontend/requirements_minimal.txt
```

### Testing
- Backend health: `curl http://localhost:8000/health`
- Chat endpoint: `curl -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"message":"Hello"}'`

## Troubleshooting

### Port Already in Use
```bash
# Kill existing processes
pkill -f "python.*main_simple"
pkill -f "streamlit.*streamlit_app_simple"
```

### Dependencies Issues
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r Backend/requirements_minimal.txt
pip install -r Frontend/requirements_minimal.txt
```

### Cannot Access from External Network
Make sure the frontend is started with:
```bash
streamlit run Frontend/streamlit_app_simple.py --server.port 8501 --server.address 0.0.0.0
```
