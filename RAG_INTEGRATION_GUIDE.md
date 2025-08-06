# RAG + Web Search Integration Guide

## 🚀 Complete Setup and Usage Guide for Cyber LLM RAG System

### Table of Contents
1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [System Architecture](#system-architecture)
4. [Quick Start](#quick-start)
5. [API Integration](#api-integration)
6. [Web Search Configuration](#web-search-configuration)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The RAG (Retrieval-Augmented Generation) system combines:
- **Local CVE Database**: 20,814 CVE entries with vector similarity search
- **Real-time Web Search**: Multiple free search engines (DuckDuckGo, SearX, Bing)
- **Intelligent Caching**: Reduces API calls and improves response times
- **Hybrid Results**: Combines local expertise with real-time intelligence

### Key Features:
✅ **Vector Similarity Search** using FAISS and Sentence Transformers  
✅ **Multi-Source Web Search** with no API keys required  
✅ **Intelligent Caching** system for performance  
✅ **Relevance Scoring** and result ranking  
✅ **Real-time Threat Intelligence** integration  

---

## Installation & Setup

### 1. Install Required Dependencies

```bash
# Navigate to project directory
cd /home/siva/project/cyber_llm

# Install RAG-specific dependencies
pip install sentence-transformers faiss-cpu aiohttp beautifulsoup4 numpy

# Or install all at once
pip install -r requirements_rag.txt
```

### 2. Verify CVE Database

```bash
# Check if complete CVE database exists
ls -la data/complete_nvd_cve_database.json

# If missing, generate it
python process_complete_nvd_dataset.py
```

### 3. Test RAG System

```bash
# Run the RAG system test
python rag_web_integration.py
```

---

## System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Query    │───▶│   RAG Controller │───▶│  Vector Search  │
└─────────────────┘    └──────────────────┘    │   (CVE Data)    │
                                 │              └─────────────────┘
                                 ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │  Web Search      │───▶│ Multiple Search │
                       │  Coordinator     │    │ Engines (Free)  │
                       └──────────────────┘    └─────────────────┘
                                 │
                                 ▼
                       ┌──────────────────┐
                       │ Result Fusion &  │
                       │ Ranking System   │
                       └──────────────────┘
```

---

## Quick Start

### Method 1: Direct Python Usage

```python
import asyncio
from rag_web_integration import CyberSecurityRAG

async def test_rag():
    # Initialize RAG system
    rag = CyberSecurityRAG()
    
    # Perform hybrid search
    results = await rag.hybrid_search("SQL injection vulnerabilities")
    
    print(f"Found {len(results['cve_results'])} CVE matches")
    print(f"Found {len(results['web_results'])} web results")
    
    # Print top CVE results
    for cve in results['cve_results'][:3]:
        print(f"CVE: {cve['cve_id']} - {cve['description'][:100]}...")

# Run the test
asyncio.run(test_rag())
```

### Method 2: Integration with Existing Backend

Add to your `Backend/main_complete_nvd.py`:

```python
# Add these imports at the top
from rag_web_integration import initialize_rag_system, perform_rag_search

# Add this endpoint
@app.get("/rag-search")
async def rag_search_endpoint(query: str, include_web: bool = True):
    """RAG-powered search endpoint"""
    try:
        results = await perform_rag_search(query, include_web)
        return {
            "status": "success",
            "query": query,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Initialize RAG on startup
@app.on_event("startup")
async def startup_event():
    await initialize_rag_system()
```

---

## API Integration

### 1. Start the Enhanced Backend

```bash
# Copy the enhanced backend
cp Backend/main_complete_nvd.py Backend/main_rag_enhanced.py

# Add RAG integration (see code above)
# Then start the enhanced backend
python Backend/main_rag_enhanced.py
```

### 2. Test RAG Endpoints

```bash
# Test RAG search
curl "http://localhost:8000/rag-search?query=buffer%20overflow&include_web=true"

# Test CVE-only search
curl "http://localhost:8000/rag-search?query=CVE-2024-0001&include_web=false"

# Test web-only search
curl "http://localhost:8000/rag-search?query=OWASP%20Top%2010&include_web=true"
```

### 3. API Response Format

```json
{
  "status": "success",
  "query": "SQL injection vulnerabilities",
  "results": {
    "cve_results": [
      {
        "cve_id": "CVE-2024-0123",
        "description": "SQL injection vulnerability in...",
        "severity": "HIGH",
        "category": "Injection",
        "cvss_score": "8.5",
        "similarity_score": 0.89,
        "source": "local_cve_database"
      }
    ],
    "web_results": [
      {
        "title": "Latest SQL Injection Prevention Techniques",
        "url": "https://example.com/sql-injection-guide",
        "snippet": "Comprehensive guide to preventing SQL injection...",
        "source": "web_duckduckgo",
        "relevance_score": 0.85,
        "timestamp": "2025-08-06T..."
      }
    ],
    "summary": {
      "total_cve_matches": 15,
      "total_web_results": 5,
      "top_categories": [["Injection", 12], ["Authorization", 3]],
      "severity_distribution": {"HIGH": 8, "MEDIUM": 5, "LOW": 2},
      "key_insights": ["Found 8 high/critical severity vulnerabilities"]
    }
  }
}
```

---

## Web Search Configuration

### Free Search Engines Used:

1. **DuckDuckGo API** (No limits, instant answers)
2. **SearX Instances** (Open source, multiple mirrors)
3. **Bing Scraping** (Fallback method)

### Search Engine Priority:
```python
# Modify search priority in rag_web_integration.py
self.search_engines = {
    'duckduckgo': self._search_duckduckgo,    # Primary: Fast, reliable
    'searx': self._search_searx,              # Secondary: Comprehensive
    'bing': self._search_bing_free            # Fallback: When others fail
}
```

### Adding Custom Search Engines:

```python
# Add to WebSearchProvider class
async def _search_custom_engine(self, query: str, max_results: int) -> List[Dict]:
    """Add your custom search implementation"""
    # Your implementation here
    pass

# Register it
self.search_engines['custom'] = self._search_custom_engine
```

---

## Advanced Usage

### 1. Custom Vector Models

```python
# Use different embedding models
from sentence_transformers import SentenceTransformer

# For better accuracy (larger model)
model = SentenceTransformer('all-mpnet-base-v2')

# For cybersecurity-specific embeddings
model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')
```

### 2. Fine-tuning Search Results

```python
# Adjust search parameters
async def enhanced_search(self, query: str):
    # Search with custom weights
    cve_results = await self.search_similar_cves(query, top_k=10)
    web_results = await self.web_search_cybersecurity(query, max_results=8)
    
    # Apply custom filtering
    filtered_cves = [cve for cve in cve_results if cve['similarity_score'] > 0.7]
    filtered_web = [web for web in web_results if web['relevance_score'] > 0.6]
    
    return {'cve_results': filtered_cves, 'web_results': filtered_web}
```

### 3. Real-time Updates

```python
# Set up periodic CVE database updates
import schedule
import time

def update_cve_database():
    """Update CVE database and rebuild index"""
    rag_system._load_cve_database()
    rag_system._build_vector_index()
    print("CVE database updated successfully")

# Schedule daily updates
schedule.every().day.at("02:00").do(update_cve_database)

# Run scheduler
while True:
    schedule.run_pending()
    time.sleep(3600)  # Check every hour
```

---

## Frontend Integration

### 1. Enhanced Streamlit Interface

Create `Frontend/streamlit_app_rag.py`:

```python
import streamlit as st
import asyncio
import requests
import json

st.set_page_config(
    page_title="Cyber LLM RAG",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 Cyber LLM RAG Search")
st.markdown("*Powered by Local CVE Database + Real-time Web Intelligence*")

# Search interface
col1, col2 = st.columns([3, 1])

with col1:
    query = st.text_input("Enter your cybersecurity query:", placeholder="e.g., SQL injection vulnerabilities, CVE-2024-0001, OWASP Top 10")

with col2:
    include_web = st.checkbox("Include Web Search", value=True)
    search_button = st.button("🔍 Search", type="primary")

if search_button and query:
    with st.spinner("Searching CVE database and web sources..."):
        try:
            # Call RAG API
            response = requests.get(
                f"http://localhost:8000/rag-search",
                params={"query": query, "include_web": include_web},
                timeout=30
            )
            
            if response.status_code == 200:
                results = response.json()['results']
                
                # Display results
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🚨 CVE Database Results")
                    for cve in results['cve_results']:
                        with st.expander(f"CVE {cve['cve_id']} - {cve['severity']}"):
                            st.write(f"**Description:** {cve['description']}")
                            st.write(f"**Category:** {cve['category']}")
                            st.write(f"**CVSS Score:** {cve['cvss_score']}")
                            st.write(f"**Similarity:** {cve['similarity_score']:.2f}")
                
                with col2:
                    st.subheader("🌐 Web Intelligence")
                    for web in results['web_results']:
                        with st.expander(f"{web['title'][:50]}..."):
                            st.write(f"**Source:** {web['source']}")
                            st.write(f"**URL:** {web['url']}")
                            st.write(f"**Snippet:** {web['snippet']}")
                            st.write(f"**Relevance:** {web['relevance_score']:.2f}")
                
                # Summary
                st.subheader("📊 Search Summary")
                summary = results['summary']
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("CVE Matches", summary['total_cve_matches'])
                
                with col2:
                    st.metric("Web Results", summary['total_web_results'])
                
                with col3:
                    high_severity = summary['severity_distribution'].get('HIGH', 0) + \
                                  summary['severity_distribution'].get('CRITICAL', 0)
                    st.metric("High/Critical CVEs", high_severity)
                
            else:
                st.error(f"Search failed: {response.text}")
                
        except Exception as e:
            st.error(f"Error: {str(e)}")
```

### 2. Start RAG-Enhanced Frontend

```bash
# Start the RAG-enhanced frontend
streamlit run Frontend/streamlit_app_rag.py --server.port 8502
```

---

## Complete Startup Script

Create `start_rag_system.sh`:

```bash
#!/bin/bash

echo "🚀 Starting Cyber LLM RAG System..."

# Activate virtual environment
source venv/bin/activate

# Install RAG dependencies
pip install sentence-transformers faiss-cpu aiohttp beautifulsoup4

# Start RAG-enhanced backend
echo "🔧 Starting RAG Backend..."
python Backend/main_rag_enhanced.py &
BACKEND_PID=$!

sleep 5

# Start RAG frontend
echo "🎨 Starting RAG Frontend..."
streamlit run Frontend/streamlit_app_rag.py --server.port 8502 &
FRONTEND_PID=$!

sleep 3

echo "✅ RAG System Ready!"
echo "🌐 Frontend: http://localhost:8502"
echo "🔧 Backend: http://localhost:8000"
echo "📖 API Docs: http://localhost:8000/docs"

# Keep running
wait
```

---

## Troubleshooting

### Common Issues & Solutions:

#### 1. **FAISS Installation Problems**
```bash
# CPU version (recommended)
pip install faiss-cpu

# If still failing, try conda
conda install faiss-cpu -c conda-forge
```

#### 2. **Sentence Transformers Download Issues**
```bash
# Pre-download models
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
```

#### 3. **Web Search Not Working**
```bash
# Test search engines individually
python -c "
import asyncio
from rag_web_integration import WebSearchProvider

async def test():
    async with WebSearchProvider() as search:
        results = await search._search_duckduckgo('test', 1)
        print(f'DuckDuckGo: {len(results)} results')

asyncio.run(test())
"
```

#### 4. **CVE Database Not Found**
```bash
# Generate complete CVE database
python process_complete_nvd_dataset.py

# Check file exists
ls -la data/complete_nvd_cve_database.json
```

#### 5. **Memory Issues with Large Dataset**
```python
# Reduce batch size for embeddings
embeddings = self.model.encode(texts, batch_size=32, show_progress_bar=True)

# Use smaller model
self.model = SentenceTransformer('all-MiniLM-L6-v2')  # 22MB vs 420MB
```

---

## Performance Optimization

### 1. **Index Optimization**
```python
# Use GPU if available
import faiss
if faiss.get_num_gpus() > 0:
    res = faiss.StandardGpuResources()
    index = faiss.index_cpu_to_gpu(res, 0, index)
```

### 2. **Caching Strategy**
```python
# Aggressive caching for common queries
CACHE_DURATION = {
    'cve_search': 3600,      # 1 hour
    'web_search': 1800,      # 30 minutes  
    'hybrid_search': 900     # 15 minutes
}
```

### 3. **Async Optimization**
```python
# Parallel search execution
async def parallel_search(self, query: str):
    cve_task = asyncio.create_task(self.search_similar_cves(query))
    web_task = asyncio.create_task(self.web_search_cybersecurity(query))
    
    cve_results, web_results = await asyncio.gather(cve_task, web_task)
    return {'cve_results': cve_results, 'web_results': web_results}
```

---

## Next Steps

1. **Start the RAG system** using the startup script
2. **Test basic functionality** with sample queries
3. **Integrate with your existing workflow**
4. **Customize search parameters** for your needs
5. **Monitor performance** and adjust caching

🎯 **Ready to revolutionize your cybersecurity intelligence with RAG + Web Search!**