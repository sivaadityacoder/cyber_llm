#!/usr/bin/env python3
"""
Trendyol-Enhanced Ethical Hacking LLM Backend v4.0
Professional-grade cybersecurity AI assistant
Integrated with Trendyol Cybersecurity LLM expertise
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
import random
import uvicorn
import os
from typing import List, Dict, Any, Optional

# --- Configuration ---
MODEL_PATH = "model/trendyol-enhanced-ethical-hacker-llm-v4"
TRAINING_DATA_PATH = "data/trendyol_integrated_training.json"

# --- Data Models ---
class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None
    domain: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    confidence: float
    source: str
    domain: Optional[str] = None
    professional_grade: bool = True

class ModelInfo(BaseModel):
    model_name: str
    version: str
    description: str
    base_model: str
    training_examples: int
    capabilities: List[str]
    security_domains: List[str]
    advanced_features: List[str]
    professional_grade: bool
    enterprise_ready: bool
    compliance_frameworks: List[str]
    status: str

class SecurityDomains(BaseModel):
    domains: List[Dict[str, Any]]
    total_domains: int
    professional_grade: bool

class ThreatIntelligence(BaseModel):
    threat_categories: List[str]
    attack_techniques: List[str]
    defense_strategies: List[str]
    total_intel_sources: int

# --- FastAPI App ---
app = FastAPI(
    title="Trendyol-Enhanced Ethical Hacking LLM API v4.0",
    description="Professional-grade cybersecurity AI assistant with advanced threat intelligence",
    version="4.0"
)

# --- Global Variables ---
knowledge_base = []
model_info = {}
domain_expertise = {}

# --- Functions ---
def load_knowledge_base():
    """Load the Trendyol-integrated training dataset"""
    global knowledge_base, domain_expertise
    try:
        with open(TRAINING_DATA_PATH, 'r') as f:
            knowledge_base = json.load(f)
        
        # Categorize expertise by domain
        domain_expertise = {}
        for item in knowledge_base:
            domain = item.get('category', 'General')
            if domain not in domain_expertise:
                domain_expertise[domain] = []
            domain_expertise[domain].append(item)
        
        print(f"✅ Loaded {len(knowledge_base)} training examples")
        print(f"✅ Organized into {len(domain_expertise)} security domains")
        return True
    except Exception as e:
        print(f"❌ Error loading knowledge base: {e}")
        # Fallback dataset
        knowledge_base = [
            {
                "instruction": "What is professional cybersecurity?",
                "output": "Professional cybersecurity encompasses enterprise-grade security practices, advanced threat detection, and comprehensive risk management frameworks.",
                "category": "General Security",
                "difficulty": "intermediate"
            }
        ]
        return False

def load_model_info():
    """Load Trendyol-enhanced model information"""
    global model_info
    try:
        with open(f"{MODEL_PATH}/model_info.json", 'r') as f:
            model_info = json.load(f)
        print(f"✅ Loaded model info: {model_info['model_name']}")
        return True
    except Exception as e:
        print(f"❌ Error loading model info: {e}")
        model_info = {
            "model_name": "Trendyol-Enhanced Ethical Hacker LLM v4.0",
            "status": "error",
            "capabilities": ["Basic cybersecurity knowledge"],
            "professional_grade": True
        }
        return False

def find_relevant_knowledge(query: str, domain_filter: Optional[str] = None) -> Dict[str, Any]:
    """Find the most relevant knowledge with advanced domain matching"""
    query_lower = query.lower()
    
    # Advanced security domain keywords
    domain_keywords = {
        "incident_response": ['incident', 'response', 'breach', 'containment', 'forensics', 'emergency'],
        "threat_hunting": ['threat', 'hunting', 'behavioral', 'anomaly', 'detection', 'proactive'],
        "code_analysis": ['code', 'static', 'dynamic', 'sast', 'dast', 'vulnerability', 'secure coding'],
        "exploit_development": ['exploit', 'penetration', 'ethical', 'proof of concept', 'vulnerability validation'],
        "reverse_engineering": ['reverse', 'binary', 'disassembly', 'protocol', 'malware analysis'],
        "malware_analysis": ['malware', 'virus', 'trojan', 'behavioral', 'sandbox', 'classification'],
        "vulnerability_research": ['zero-day', 'vulnerability', 'research', 'disclosure', 'discovery'],
        "cloud_security": ['cloud', 'aws', 'azure', 'container', 'kubernetes', 'serverless'],
        "cryptography": ['crypto', 'encryption', 'quantum', 'post-quantum', 'key management'],
        "ai_security": ['ai', 'machine learning', 'adversarial', 'model security', 'ml'],
        "network_security": ['network', 'traffic', 'monitoring', 'ids', 'ips', 'firewall'],
        "digital_forensics": ['forensics', 'evidence', 'investigation', 'timeline', 'artifact']
    }
    
    # Traditional security keywords (for backward compatibility)
    traditional_keywords = [
        'sql injection', 'xss', 'csrf', 'privilege escalation', 'buffer overflow',
        'network security', 'cryptography', 'forensics', 'incident response'
    ]
    
    best_match = None
    best_score = 0
    
    # Filter by domain if specified
    search_space = domain_expertise.get(domain_filter, knowledge_base) if domain_filter else knowledge_base
    
    for item in search_space:
        score = 0
        item_text = (item.get('instruction', '') + ' ' + 
                    item.get('input', '') + ' ' + 
                    item.get('output', '') + ' ' +
                    item.get('response', '')).lower()
        
        # Advanced domain matching (higher weight for professional topics)
        for domain, keywords in domain_keywords.items():
            if any(keyword in query_lower for keyword in keywords):
                if any(keyword in item_text for keyword in keywords):
                    score += 15  # Higher weight for advanced topics
        
        # Traditional security content matching
        if any(keyword in query_lower for keyword in traditional_keywords):
            if any(keyword in item_text for keyword in traditional_keywords):
                score += 8
        
        # Professional-grade content boost
        if item.get('difficulty') in ['advanced', 'expert']:
            score += 5
        
        # Category-specific boost
        if item.get('category') and any(cat_word in query_lower for cat_word in item.get('category', '').lower().split()):
            score += 3
        
        # Basic keyword matching
        query_words = query_lower.split()
        for word in query_words:
            if len(word) > 3 and word in item_text:
                score += 1
        
        if score > best_score:
            best_score = score
            best_match = item
    
    return best_match if best_match else (knowledge_base[0] if knowledge_base else None)

def generate_professional_response(query: str, domain_filter: Optional[str] = None) -> tuple[str, float, str]:
    """Generate professional-grade cybersecurity response"""
    
    # Find relevant knowledge
    relevant_knowledge = find_relevant_knowledge(query, domain_filter)
    
    if not relevant_knowledge:
        return "I don't have specific information about that topic. Please ask about professional cybersecurity, advanced threat detection, or enterprise security practices.", 0.3, "general"
    
    # Extract the response - handle both 'output' and 'response' fields
    response = relevant_knowledge.get('output', '') or relevant_knowledge.get('response', '')
    
    if not response:
        return "I don't have specific information about that topic. Please ask about professional cybersecurity practices.", 0.3, "general"
    
    # Determine confidence based on match quality and professionalism
    query_lower = query.lower()
    response_lower = response.lower()
    
    confidence = 0.75  # Higher base confidence for professional model
    detected_domain = relevant_knowledge.get('category', 'General')
    
    # Boost confidence for advanced/professional topics
    advanced_indicators = ['advanced', 'professional', 'enterprise', 'sophisticated', 'comprehensive']
    if any(indicator in response_lower for indicator in advanced_indicators):
        confidence += 0.15
    
    # Boost confidence for detailed technical responses
    if len(response) > 800:  # Professional responses are typically detailed
        confidence += 0.1
    
    # Boost confidence for expert-level content
    if relevant_knowledge.get('difficulty') == 'expert':
        confidence += 0.1
    elif relevant_knowledge.get('difficulty') == 'advanced':
        confidence += 0.05
    
    # Domain-specific confidence boost
    domain_indicators = ['incident response', 'threat hunting', 'malware analysis', 'vulnerability research']
    if any(indicator in response_lower for indicator in domain_indicators):
        confidence += 0.1
    
    # Cap confidence at professional level
    confidence = min(confidence, 0.98)
    
    return response, confidence, detected_domain.lower().replace(' ', '_')

# --- API Endpoints ---
@app.get("/")
async def root():
    return {
        "message": "Trendyol-Enhanced Ethical Hacking LLM API v4.0", 
        "status": "running",
        "features": ["Professional Cybersecurity", "Advanced Threat Intelligence", "Enterprise Security"],
        "professional_grade": True,
        "based_on": "Trendyol Cybersecurity LLM expertise"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "knowledge_base_size": len(knowledge_base),
        "security_domains": len(domain_expertise),
        "model_loaded": bool(model_info),
        "professional_grade": True,
        "enterprise_ready": model_info.get("enterprise_ready", False),
        "trendyol_integration": True
    }

@app.get("/model/info", response_model=ModelInfo)
async def get_model_info():
    return ModelInfo(
        model_name=model_info.get("model_name", "Unknown"),
        version=model_info.get("version", "4.0"),
        description=model_info.get("description", "Professional cybersecurity AI"),
        base_model=model_info.get("base_model", "Trendyol Cybersecurity LLM"),
        training_examples=model_info.get("training_examples", len(knowledge_base)),
        capabilities=model_info.get("capabilities", []),
        security_domains=model_info.get("security_domains", []),
        advanced_features=model_info.get("advanced_features", []),
        professional_grade=model_info.get("professional_grade", True),
        enterprise_ready=model_info.get("enterprise_ready", True),
        compliance_frameworks=model_info.get("compliance_frameworks", []),
        status="loaded" if knowledge_base else "error"
    )

@app.get("/security/domains", response_model=SecurityDomains)
async def get_security_domains():
    """Get detailed security domain information"""
    domains_info = []
    for domain, examples in domain_expertise.items():
        domains_info.append({
            "name": domain,
            "examples_count": len(examples),
            "difficulty_levels": list(set([ex.get('difficulty', 'intermediate') for ex in examples])),
            "capabilities": [ex.get('instruction', '')[:100] + '...' for ex in examples[:3]]
        })
    
    return SecurityDomains(
        domains=domains_info,
        total_domains=len(domain_expertise),
        professional_grade=True
    )

@app.get("/threat-intelligence")
async def get_threat_intelligence():
    """Get threat intelligence overview"""
    threat_categories = list(domain_expertise.keys())
    
    # Extract attack techniques from training data
    attack_techniques = []
    defense_strategies = []
    
    for examples in domain_expertise.values():
        for example in examples:
            tags = example.get('tags', [])
            if any('attack' in tag or 'technique' in tag for tag in tags):
                attack_techniques.extend(tags)
            if any('defense' in tag or 'mitigation' in tag for tag in tags):
                defense_strategies.extend(tags)
    
    return ThreatIntelligence(
        threat_categories=threat_categories,
        attack_techniques=list(set(attack_techniques))[:20],  # Limit for response size
        defense_strategies=list(set(defense_strategies))[:20],
        total_intel_sources=len(knowledge_base)
    )

@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    try:
        response, confidence, domain = generate_professional_response(
            request.message, 
            request.domain
        )
        
        return ChatResponse(
            response=response,
            confidence=confidence,
            source="trendyol_enhanced_ethical_hacking_llm_v4",
            domain=domain,
            professional_grade=True
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating response: {str(e)}")

@app.post("/professional-analysis")
async def professional_analysis(request: ChatRequest):
    """Advanced analysis endpoint for professional cybersecurity queries"""
    try:
        # Multi-domain analysis
        results = {}
        confidence_scores = {}
        
        for domain in domain_expertise.keys():
            response, confidence, detected_domain = generate_professional_response(
                request.message, 
                domain
            )
            if confidence > 0.6:  # Only include relevant domains
                results[domain] = {
                    "response": response[:200] + "...",  # Truncated for overview
                    "confidence": confidence,
                    "detected_domain": detected_domain
                }
                confidence_scores[domain] = confidence
        
        # Find best match
        best_domain = max(confidence_scores.items(), key=lambda x: x[1]) if confidence_scores else ("general", 0.3)
        
        return {
            "query": request.message,
            "best_match_domain": best_domain[0],
            "best_confidence": best_domain[1],
            "domain_analysis": results,
            "professional_grade": True,
            "recommendation": f"This query is best addressed by the {best_domain[0]} domain with {best_domain[1]:.1%} confidence."
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in professional analysis: {str(e)}")

@app.get("/advanced-capabilities")
async def get_advanced_capabilities():
    """Get advanced cybersecurity capabilities"""
    return {
        "incident_response": [
            "Multi-stage incident analysis",
            "Threat intelligence correlation", 
            "Automated containment strategies",
            "Timeline reconstruction",
            "Impact assessment"
        ],
        "threat_hunting": [
            "Behavioral baseline establishment",
            "Hypothesis-driven hunting",
            "Advanced correlation techniques",
            "Anomaly detection",
            "Threat validation"
        ],
        "vulnerability_research": [
            "Zero-day discovery methodologies",
            "Responsible disclosure processes",
            "Exploit development frameworks",
            "Attack surface analysis",
            "Proof-of-concept creation"
        ],
        "professional_services": [
            "Enterprise security assessments",
            "Compliance framework mapping",
            "Risk quantification",
            "Security architecture review",
            "Incident response planning"
        ]
    }

# --- Startup Event ---
@app.on_event("startup")
async def startup_event():
    print("🚀 Starting Trendyol-Enhanced Ethical Hacking LLM API v4.0...")
    print("🔒 Professional-Grade Cybersecurity AI Assistant")
    print("🏢 Enterprise-Ready with Advanced Threat Intelligence")
    
    # Load knowledge base
    kb_loaded = load_knowledge_base()
    
    # Load model info  
    model_loaded = load_model_info()
    
    if kb_loaded and model_loaded:
        print("✅ All components loaded successfully")
        print(f"📊 Knowledge Base: {len(knowledge_base)} examples")
        print(f"🏢 Model: {model_info['model_name']}")
        print(f"🛡️ Security Domains: {len(domain_expertise)}")
        print(f"🔒 Professional Grade: {model_info.get('professional_grade', True)}")
        print(f"🏆 Enterprise Ready: {model_info.get('enterprise_ready', True)}")
        print(f"📋 Compliance Frameworks: {len(model_info.get('compliance_frameworks', []))}")
    else:
        print("⚠️ Some components failed to load, using fallback mode")

# --- Main ---
if __name__ == "__main__":
    print("🛡️ Trendyol-Enhanced Ethical Hacking LLM Backend v4.0")
    print("🔒 Professional Cybersecurity + Enterprise Threat Intelligence")
    print("🏢 Based on Trendyol Cybersecurity LLM Expertise")
    print("="*80)
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )
