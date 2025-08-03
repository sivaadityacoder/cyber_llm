"""
🛡️ SIMPLE WORKING BACKEND FOR CVE TESTING
Basic FastAPI backend to test CVE intelligence integration
"""

import json
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Simple request models
class ChatRequest(BaseModel):
    message: str
    domain: str = None

# Load CVE enhanced training data
def load_training_data():
    try:
        data_file = "/home/coder/startup/ownllm/data/trendyol_cve_enhanced_training.json"
        if os.path.exists(data_file):
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading training data: {e}")
    return []

# Initialize training data
training_data = load_training_data()
cve_count = len([ex for ex in training_data if 'cve_id' in ex.get('metadata', {})])

print(f"✅ Loaded {len(training_data)} training examples")
print(f"🔍 CVE Intelligence entries: {cve_count}")

# FastAPI app
app = FastAPI(
    title="🛡️ CVE-Enhanced Cybersecurity AI Backend",
    description="Simple backend with CVE intelligence integration",
    version="5.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model": "CVE-Enhanced Cybersecurity AI",
        "version": "5.0.0",
        "training_examples": len(training_data),
        "cve_intelligence_entries": cve_count,
        "professional_grade": True,
        "cve_intelligence_enabled": True
    }

@app.get("/model/info")
async def get_model_info():
    """Get model information"""
    return {
        "model_name": "Trendyol-Enhanced CVE Intelligence AI",
        "version": "5.0.0",
        "description": "Professional cybersecurity AI with CVE intelligence integration",
        "training_examples": len(training_data),
        "cve_intelligence_entries": cve_count,
        "features": [
            "CVE Intelligence Integration",
            "Professional Vulnerability Assessment",
            "Enterprise Threat Intelligence",
            "Advanced Risk Assessment",
            "Compliance Framework Support"
        ],
        "status": "operational"
    }

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """Simple chat endpoint with CVE intelligence"""
    message = request.message.lower()
    
    # Find relevant examples
    relevant_examples = []
    for example in training_data:
        question = example.get('question', '').lower()
        if any(word in question for word in message.split()[:3]):
            relevant_examples.append(example)
    
    # Check for CVE mentions
    cve_context = ""
    if any(keyword in message for keyword in ['cve', 'vulnerability', 'exploit']):
        cve_examples = [ex for ex in training_data if 'cve_id' in ex.get('metadata', {})]
        if cve_examples:
            cve_context = f"Found {len(cve_examples)} CVE intelligence entries. "
    
    # Generate response
    if relevant_examples:
        best_example = relevant_examples[0]
        response = best_example.get('answer', '')
        confidence = 0.9
        domain = best_example.get('domain', 'cybersecurity')
    else:
        response = f"""**Professional Cybersecurity Analysis:**

{cve_context}This query relates to cybersecurity best practices. I can provide expert guidance based on professional standards and vulnerability intelligence.

**Key Professional Recommendations:**
- Implement defense-in-depth security strategies
- Conduct regular vulnerability assessments
- Maintain compliance with security frameworks (SOC2, ISO27001)
- Follow ethical hacking guidelines
- Establish comprehensive incident response procedures

**CVE Intelligence Available:**
- {cve_count} real-world vulnerability entries from NVD 2025
- Professional risk assessment capabilities
- Enterprise-grade threat intelligence
- CVSS-based severity scoring

For specific vulnerabilities or security concerns, please provide more details for targeted professional guidance."""
        confidence = 0.75
        domain = "general_cybersecurity"
    
    return {
        "response": response,
        "confidence": confidence,
        "domain": domain,
        "cve_intelligence_included": bool(cve_context),
        "professional_grade": True
    }

@app.get("/security/domains")
async def get_security_domains():
    """Get security domains from training data"""
    domains = set()
    for example in training_data:
        domain = example.get('domain', 'general')
        domains.add(domain)
    
    domain_list = []
    for domain in domains:
        count = len([ex for ex in training_data if ex.get('domain') == domain])
        domain_list.append({
            "name": domain,
            "examples_count": count
        })
    
    return {
        "domains": domain_list,
        "total_domains": len(domain_list)
    }

@app.get("/cve/intelligence/summary")
async def get_cve_summary():
    """Get CVE intelligence summary"""
    cve_examples = [ex for ex in training_data if 'cve_id' in ex.get('metadata', {})]
    
    severity_count = {}
    for example in cve_examples:
        severity = example.get('metadata', {}).get('severity', 'unknown')
        severity_count[severity] = severity_count.get(severity, 0) + 1
    
    return {
        "total_cves": len(cve_examples),
        "severity_distribution": severity_count,
        "intelligence_quality": "professional_grade",
        "data_source": "NVD_CVE_2025"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "🛡️ CVE-Enhanced Cybersecurity AI Backend v5.0",
        "description": "Professional security intelligence with CVE integration",
        "health_check": "/health",
        "documentation": "/docs",
        "cve_intelligence": f"{cve_count} entries available"
    }

if __name__ == "__main__":
    print("🚀 Starting CVE-Enhanced Cybersecurity Backend...")
    print(f"📊 Training examples: {len(training_data)}")
    print(f"🔍 CVE intelligence: {cve_count} entries")
    print("🌐 Server starting on http://0.0.0.0:8000")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
