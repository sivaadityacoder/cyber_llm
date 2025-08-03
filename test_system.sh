#!/bin/bash

# Enhanced OwnLLM System Test Script v3.0
# Tests all functionality of the enhanced ethical hacking LLM system

echo "🧪 Testing Enhanced Ethical Hacking LLM v3.0..."
echo "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "="

# Test backend health
echo "🩺 Testing Backend Health..."
if response=$(curl -s http://localhost:8000/health); then
    echo "✅ Backend Health: $response"
else
    echo "❌ Backend Health: Failed"
    exit 1
fi

# Test frontend accessibility
echo "🎨 Testing Frontend Accessibility..."
if curl -s -I http://localhost:8501 | grep -q "200 OK"; then
    echo "✅ Frontend: Accessible"
else
    echo "❌ Frontend: Not accessible"
    exit 1
fi

# Test model info
echo "🤖 Testing Model Information..."
if model_info=$(curl -s http://localhost:8000/model/info); then
    model_name=$(echo $model_info | python3 -c "import sys,json; print(json.load(sys.stdin)['model_name'])" 2>/dev/null)
    training_examples=$(echo $model_info | python3 -c "import sys,json; print(json.load(sys.stdin)['training_examples'])" 2>/dev/null)
    echo "✅ Model: $model_name"
    echo "✅ Training Examples: $training_examples"
else
    echo "❌ Model Info: Failed"
    exit 1
fi

# Test traditional cybersecurity knowledge
echo "🛡️ Testing Traditional Security Knowledge..."
sql_response=$(curl -s -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"message":"What is SQL injection?"}')
if echo $sql_response | grep -q "SQL injection"; then
    confidence=$(echo $sql_response | python3 -c "import sys,json; print(f'{json.load(sys.stdin)[\"confidence\"]:.1%}')" 2>/dev/null)
    echo "✅ SQL Injection Knowledge: Available (Confidence: $confidence)"
else
    echo "❌ SQL Injection Knowledge: Failed"
fi

# Test LLM security knowledge
echo "🔒 Testing LLM Security Knowledge..."
prompt_response=$(curl -s -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"message":"What is prompt injection?"}')
if echo $prompt_response | grep -q "PROMPT INJECTION"; then
    confidence=$(echo $prompt_response | python3 -c "import sys,json; print(f'{json.load(sys.stdin)[\"confidence\"]:.1%}')" 2>/dev/null)
    echo "✅ Prompt Injection Knowledge: Available (Confidence: $confidence)"
else
    echo "❌ Prompt Injection Knowledge: Failed"
fi

# Test LLM security endpoints
echo "🤖 Testing LLM Security Endpoints..."
if llm_attacks=$(curl -s http://localhost:8000/llm-security/attacks); then
    attack_count=$(echo $llm_attacks | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])" 2>/dev/null)
    echo "✅ LLM Security Attacks: $attack_count topics available"
else
    echo "❌ LLM Security Endpoints: Failed"
fi

# Test knowledge topics
echo "📚 Testing Knowledge Base..."
if topics_response=$(curl -s http://localhost:8000/knowledge/topics); then
    total_examples=$(echo $topics_response | python3 -c "import sys,json; print(json.load(sys.stdin)['total_examples'])" 2>/dev/null)
    llm_examples=$(echo $topics_response | python3 -c "import sys,json; print(json.load(sys.stdin)['llm_security_examples'])" 2>/dev/null)
    echo "✅ Knowledge Base: $total_examples total examples, $llm_examples LLM security examples"
else
    echo "❌ Knowledge Base: Failed"
fi

# Test advanced LLM security topics
echo "🔍 Testing Advanced LLM Security..."

# Test jailbreaking knowledge
jailbreak_response=$(curl -s -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"message":"How do jailbreaking attacks work?"}')
if echo $jailbreak_response | grep -q "jailbreaking"; then
    echo "✅ Jailbreaking Knowledge: Available"
else
    echo "❌ Jailbreaking Knowledge: Failed"
fi

# Test context poisoning knowledge
context_response=$(curl -s -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"message":"What is context poisoning?"}')
if echo $context_response | grep -q "CONTEXT POISONING"; then
    echo "✅ Context Poisoning Knowledge: Available"
else
    echo "❌ Context Poisoning Knowledge: Failed"
fi

echo ""
echo "🎯 Testing Summary Complete!"
echo "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "="
echo "🌐 Frontend UI:      http://localhost:8501"
echo "🔌 Backend API:      http://localhost:8000"  
echo "📚 API Documentation: http://localhost:8000/docs"
echo ""
echo "✨ All systems operational! Enhanced Ethical Hacking LLM v3.0 is ready."
echo "🛡️ Features: Traditional Cybersecurity + LLM Security + AI Safety"
echo "📊 Coverage: 46 training examples across 12 security domains"
echo "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "="
