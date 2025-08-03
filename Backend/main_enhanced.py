#!/usr/bin/env python3
"""
Enhanced Ethical Hacking LLM Backend v3.0
Includes comprehensive cybersecurity + LLM security capabilities
Based on the LLM Hacking Database
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
import random
import uvicorn
import os
from typing import List, Dict, Any

# --- Configuration ---
MODEL_PATH = "model/enhanced-ethical-hacker-llm-v3"
TRAINING_DATA_PATH = "data/enhanced_ethical_hacker_training.json"

# --- Data Models ---
class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    confidence: float
    source: str

class ModelInfo(BaseModel):
    model_name: str
    version: str
    description: str
    training_examples: int
    capabilities: List[str]
    security_domains: List[str]
    llm_security_coverage: List[str]
    status: str

class KnowledgeTopics(BaseModel):
    available_topics: List[str]
    total_examples: int
    llm_security_examples: int

# --- FastAPI App ---
app = FastAPI(
    title="Enhanced Ethical Hacking LLM API v3.0",
    description="AI assistant for cybersecurity and LLM security",
    version="3.0"
)

# --- Global Variables ---
knowledge_base = []
model_info = {}

# --- Functions ---
def load_knowledge_base():
    """Load the comprehensive training dataset"""
    global knowledge_base
    try:
        with open(TRAINING_DATA_PATH, 'r') as f:
            knowledge_base = json.load(f)
        print(f"✅ Loaded {len(knowledge_base)} training examples")
        return True
    except Exception as e:
        print(f"❌ Error loading knowledge base: {e}")
        # Fallback dataset
        knowledge_base = [
            {
                "instruction": "What is ethical hacking?",
                "output": "Ethical hacking is the practice of testing systems for vulnerabilities with proper authorization to improve security.",
                "category": "General Security",
                "confidence": 0.9
            }
        ]
        return False

def load_model_info():
    """Load model information"""
    global model_info
    try:
        with open(f"{MODEL_PATH}/model_info.json", 'r') as f:
            model_info = json.load(f)
        print(f"✅ Loaded model info: {model_info['model_name']}")
        return True
    except Exception as e:
        print(f"❌ Error loading model info: {e}")
        model_info = {
            "model_name": "Enhanced Ethical Hacker LLM v3.0",
            "status": "error",
            "capabilities": ["Basic cybersecurity knowledge"]
        }
        return False

def find_relevant_knowledge(query: str) -> Dict[str, Any]:
    """Find the most relevant knowledge for a query"""
    query_lower = query.lower()
    
    # LLM Security keywords
    llm_security_keywords = [
        'prompt injection', 'jailbreak', 'llm', 'ai safety', 'model security',
        'prompt leak', 'context poison', 'parameter bomb', 'emotional manipulation',
        'file injection', 'killswitch', 'llm attack', 'ai attack', 'model attack'
    ]
    
    # Traditional security keywords  
    security_keywords = [
        'sql injection', 'xss', 'csrf', 'privilege escalation', 'buffer overflow',
        'network security', 'cryptography', 'forensics', 'incident response'
    ]
    
    best_match = None
    best_score = 0
    
    for item in knowledge_base:
        score = 0
        item_text = (item.get('instruction', '') + ' ' + 
                    item.get('input', '') + ' ' + 
                    item.get('output', '') + ' ' +
                    item.get('response', '')).lower()
        
        # Check for LLM security content (higher weight)
        if any(keyword in query_lower for keyword in llm_security_keywords):
            if any(keyword in item_text for keyword in llm_security_keywords):
                score += 10
        
        # Check for traditional security content
        if any(keyword in query_lower for keyword in security_keywords):
            if any(keyword in item_text for keyword in security_keywords):
                score += 5
        
        # Basic keyword matching
        query_words = query_lower.split()
        for word in query_words:
            if len(word) > 3 and word in item_text:
                score += 1
        
        if score > best_score:
            best_score = score
            best_match = item
    
    return best_match if best_match else knowledge_base[0]

def generate_response(query: str) -> tuple[str, float]:
    """Generate a response based on the knowledge base"""
    
    # Find relevant knowledge
    relevant_knowledge = find_relevant_knowledge(query)
    
    if not relevant_knowledge:
        return "I don't have specific information about that topic. Please ask about cybersecurity, ethical hacking, or LLM security.", 0.3
    
    # Extract the response - handle both 'output' and 'response' fields
    response = relevant_knowledge.get('output', '') or relevant_knowledge.get('response', '')
    
    if not response:
        return "I don't have specific information about that topic. Please ask about cybersecurity, ethical hacking, or LLM security.", 0.3
    
    # Determine confidence based on match quality
    query_lower = query.lower()
    response_lower = response.lower()
    
    confidence = 0.7  # Base confidence
    
    # Boost confidence for LLM security topics
    llm_keywords = ['prompt', 'injection', 'jailbreak', 'llm', 'model', 'ai safety']
    if any(keyword in query_lower for keyword in llm_keywords):
        if any(keyword in response_lower for keyword in llm_keywords):
            confidence += 0.2
    
    # Boost confidence for detailed responses
    if len(response) > 500:
        confidence += 0.1
    
    # Cap confidence
    confidence = min(confidence, 0.95)
    
    return response, confidence

# --- API Endpoints ---
@app.get("/")
async def root():
    return {
        "message": "Enhanced Ethical Hacking LLM API v3.0", 
        "status": "running",
        "features": ["Cybersecurity", "LLM Security", "AI Safety"]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "knowledge_base_size": len(knowledge_base),
        "model_loaded": bool(model_info),
        "llm_security_enabled": True
    }

@app.get("/model/info", response_model=ModelInfo)
async def get_model_info():
    return ModelInfo(
        model_name=model_info.get("model_name", "Unknown"),
        version=model_info.get("version", "3.0"),
        description=model_info.get("description", "Enhanced ethical hacking AI"),
        training_examples=model_info.get("training_examples", len(knowledge_base)),
        capabilities=model_info.get("capabilities", []),
        security_domains=model_info.get("security_domains", []),
        llm_security_coverage=model_info.get("llm_security_coverage", []),
        status="loaded" if knowledge_base else "error"
    )

@app.get("/knowledge/topics", response_model=KnowledgeTopics)
async def get_knowledge_topics():
    # Extract unique categories
    categories = set()
    llm_security_count = 0
    
    for item in knowledge_base:
        category = item.get('category', 'General')
        categories.add(category)
        if 'LLM Security' in category or 'llm' in category.lower():
            llm_security_count += 1
    
    return KnowledgeTopics(
        available_topics=sorted(list(categories)),
        total_examples=len(knowledge_base),
        llm_security_examples=llm_security_count
    )

@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    try:
        response, confidence = generate_response(request.message)
        
        return ChatResponse(
            response=response,
            confidence=confidence,
            source="enhanced_ethical_hacking_llm_v3"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating response: {str(e)}")

@app.get("/llm-security/attacks")
async def get_llm_attacks():
    """Get information about LLM attack types"""
    attacks = []
    for item in knowledge_base:
        if 'LLM Security' in item.get('category', ''):
            attacks.append({
                'topic': item.get('instruction', ''),
                'category': item.get('category', ''),
                'tags': item.get('tags', [])
            })
    return {"attacks": attacks, "total": len(attacks)}

@app.get("/security/domains")
async def get_security_domains():
    """Get all security domains covered"""
    domains = model_info.get("security_domains", [])
    return {"domains": domains, "count": len(domains)}

# --- Startup Event ---
@app.on_event("startup")
async def startup_event():
    print("🚀 Starting Enhanced Ethical Hacking LLM API v3.0...")
    
    # Load knowledge base
    kb_loaded = load_knowledge_base()
    
    # Load model info  
    model_loaded = load_model_info()
    
    if kb_loaded and model_loaded:
        print("✅ All components loaded successfully")
        print(f"📊 Knowledge Base: {len(knowledge_base)} examples")
        print(f"🤖 Model: {model_info['model_name']}")
        print(f"🛡️ Security Domains: {len(model_info.get('security_domains', []))}")
        print(f"🔒 LLM Security Features: {len(model_info.get('llm_security_coverage', []))}")
    else:
        print("⚠️ Some components failed to load, using fallback mode")

# --- Main ---
if __name__ == "__main__":
    print("🛡️ Enhanced Ethical Hacking LLM Backend v3.0")
    print("🔒 Features: Cybersecurity + LLM Security + AI Safety")
    print("="*60)
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )
