from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import json
import uvicorn
from datetime import datetime

# --- Configuration ---
app = FastAPI(title="Ethical Hacking LLM Backend", description="AI Assistant for Cybersecurity and Ethical Hacking")

# Load trained model information
MODEL_PATH = "model/comprehensive-ethical-hacker-llm-v2"
try:
    with open(f"{MODEL_PATH}/model_info.json", "r") as f:
        model_info = json.load(f)
    with open(f"{MODEL_PATH}/training_log.json", "r") as f:
        training_log = json.load(f)
    MODEL_LOADED = True
except FileNotFoundError:
    model_info = {"model_name": "Not trained yet"}
    training_log = {"status": "not_trained"}
    MODEL_LOADED = False

# Load training data for knowledge base
try:
    # Try comprehensive dataset first
    with open("data/comprehensive_train_dataset.json", "r") as f:
        knowledge_base = json.load(f)
except FileNotFoundError:
    try:
        # Fallback to basic dataset
        with open("data/train_dataset.json", "r") as f:
            knowledge_base = json.load(f)
    except FileNotFoundError:
        knowledge_base = []

# --- Models ---
class ChatMessage(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    confidence: float = 0.0
    source: str = "ethical_hacking_llm"

class ModelInfo(BaseModel):
    model_name: str
    status: str
    capabilities: list = []
    training_examples: int = 0

# --- Helper Functions ---
def find_best_match(query: str):
    """Find the best matching response from our knowledge base"""
    query_lower = query.lower()
    best_match = None
    best_score = 0
    
    for item in knowledge_base:
        instruction = item['instruction'].lower()
        response = item['response']
        
        # Simple keyword matching
        common_words = set(query_lower.split()) & set(instruction.split())
        score = len(common_words)
        
        # Boost score for exact phrase matches
        if any(phrase in instruction for phrase in query_lower.split() if len(phrase) > 3):
            score += 2
        
        if score > best_score:
            best_score = score
            best_match = response
    
    return best_match, best_score

def generate_ethical_response(query: str):
    """Generate an ethical hacking response"""
    query_lower = query.lower()
    
    # Check for malicious intent
    malicious_keywords = ['hack into', 'break into', 'steal', 'damage', 'illegal', 'unauthorized access']
    if any(keyword in query_lower for keyword in malicious_keywords):
        return ("I'm designed to provide information about ethical hacking and cybersecurity for defensive purposes only. "
                "I cannot and will not provide information for malicious activities, unauthorized access, or illegal actions. "
                "Please ask about defensive security measures, ethical penetration testing, or educational cybersecurity topics."), 0.9
    
    # Try to find a match in our knowledge base
    best_match, score = find_best_match(query)
    
    if best_match and score > 0:
        confidence = min(0.9, score * 0.2)
        return best_match, confidence
    
    # Generate a general response for cybersecurity topics
    cybersecurity_keywords = ['security', 'vulnerability', 'penetration', 'ethical', 'cyber', 'hack', 'attack', 'defense']
    if any(keyword in query_lower for keyword in cybersecurity_keywords):
        return ("I understand you're asking about cybersecurity. While I'm trained on ethical hacking concepts, "
                "I don't have specific information about your query. I can help with topics like web application security, "
                "network security, incident response, digital forensics, and ethical penetration testing methodologies. "
                "Could you please be more specific about what aspect of cybersecurity you'd like to learn about?"), 0.3
    
    # Default response
    return ("I'm an AI assistant specialized in ethical hacking and cybersecurity. I can help with topics like "
            "vulnerability assessment, penetration testing methodologies, security best practices, incident response, "
            "and defensive security measures. How can I assist you with cybersecurity today?"), 0.2

# --- Routes ---
@app.get("/")
async def root():
    return {
        "message": "Ethical Hacking LLM Backend is running!",
        "model_status": "trained" if MODEL_LOADED else "not_trained",
        "capabilities": ["Web Security", "Network Security", "System Security", "Cryptography", "Incident Response"]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "message": "Backend is operational",
        "model_loaded": MODEL_LOADED,
        "knowledge_base_size": len(knowledge_base)
    }

@app.get("/model/info", response_model=ModelInfo)
async def get_model_info():
    return ModelInfo(
        model_name=model_info.get("model_name", "Ethical Hacking LLM"),
        status="trained" if MODEL_LOADED else "not_trained",
        capabilities=model_info.get("capabilities", []),
        training_examples=model_info.get("training_examples", len(knowledge_base))
    )

@app.post("/chat", response_model=ChatResponse)
async def chat(message: ChatMessage):
    if not message.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    # Generate response using our ethical hacking model
    response_text, confidence = generate_ethical_response(message.message)
    
    return ChatResponse(
        response=response_text,
        confidence=confidence,
        source="ethical_hacking_llm"
    )

@app.post("/analyze/vulnerability")
async def analyze_vulnerability():
    return {
        "message": "Vulnerability analysis endpoint",
        "status": "This feature requires specific vulnerability data input",
        "capabilities": ["Web app vulnerabilities", "Network security assessment", "Code review"]
    }

@app.get("/knowledge/topics")
async def get_knowledge_topics():
    """Get available knowledge topics"""
    topics = set()
    for item in knowledge_base:
        instruction = item['instruction'].lower()
        if 'sql' in instruction or 'xss' in instruction or 'csrf' in instruction:
            topics.add("Web Application Security")
        elif 'network' in instruction or 'port' in instruction:
            topics.add("Network Security")
        elif 'password' in instruction or 'encrypt' in instruction:
            topics.add("Cryptography")
        elif 'incident' in instruction or 'forensic' in instruction:
            topics.add("Incident Response")
        elif 'social' in instruction:
            topics.add("Social Engineering")
        elif 'legal' in instruction or 'ethical' in instruction:
            topics.add("Ethics & Legal")
        else:
            topics.add("General Security")
    
    return {
        "available_topics": list(topics),
        "total_examples": len(knowledge_base),
        "model_status": "trained" if MODEL_LOADED else "not_trained"
    }

@app.get("/examples/{topic}")
async def get_topic_examples(topic: str):
    """Get example questions for a specific topic"""
    topic_examples = []
    
    for item in knowledge_base:
        instruction = item['instruction']
        if topic.lower() in instruction.lower():
            topic_examples.append(instruction)
    
    return {
        "topic": topic,
        "examples": topic_examples[:5],  # Return first 5 examples
        "total_available": len(topic_examples)
    }

# --- Main ---
if __name__ == "__main__":
    print("🚀 Starting Ethical Hacking LLM Backend...")
    print(f"📊 Model Status: {'Trained' if MODEL_LOADED else 'Not Trained'}")
    print(f"📚 Knowledge Base: {len(knowledge_base)} examples")
    uvicorn.run(app, host="0.0.0.0", port=8000)
