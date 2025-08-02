"""
LLM Manager for handling local language models.
"""

import os
import asyncio
from typing import List, Dict, Optional, Any
import logging
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)


class LLMManager:
    """Manages local LLM models and inference."""
    
    def __init__(self):
        self.models_path = Path(settings.llm_model_path)
        self.loaded_models = {}
        self.current_model = None
        self._ensure_models_directory()
        
    def _ensure_models_directory(self):
        """Ensure models directory exists."""
        self.models_path.mkdir(parents=True, exist_ok=True)
        
    async def load_model(self, model_name: str) -> bool:
        """Load a specific model."""
        try:
            model_path = self.models_path / model_name
            
            if not model_path.exists():
                logger.error(f"Model file not found: {model_path}")
                return False
            
            # For demonstration, we'll simulate model loading
            # In production, use llama-cpp-python or similar
            logger.info(f"Loading model: {model_name}")
            
            # Simulate loading time
            await asyncio.sleep(1)
            
            # Mock model object
            model_info = {
                "name": model_name,
                "path": str(model_path),
                "loaded": True,
                "context_length": settings.max_tokens,
                "model_type": "gguf"
            }
            
            self.loaded_models[model_name] = model_info
            self.current_model = model_name
            
            logger.info(f"Model {model_name} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            return False
    
    async def generate_response(
        self, 
        messages: List[Dict[str, str]], 
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048
    ) -> Dict[str, Any]:
        """Generate response from the LLM."""
        try:
            # Use specified model or default
            model_name = model or settings.default_model
            
            # Load model if not already loaded
            if model_name not in self.loaded_models:
                if not await self.load_model(model_name):
                    # Fallback to mock response if model loading fails
                    return await self._generate_mock_response(messages, model_name)
            
            # Extract user message for processing
            user_message = ""
            for msg in messages:
                if msg["role"] == "user":
                    user_message = msg["content"]
                    break
            
            # Generate response based on ethical hacking context
            response_content = await self._generate_ethical_hacking_response(user_message)
            
            return {
                "content": response_content,
                "model": model_name,
                "tokens_used": len(response_content.split()) * 1.3,  # Rough estimate
                "finish_reason": "stop"
            }
            
        except Exception as e:
            logger.error(f"Response generation failed: {e}")
            return await self._generate_mock_response(messages, model_name)
    
    async def _generate_ethical_hacking_response(self, user_message: str) -> str:
        """Generate contextually appropriate ethical hacking response."""
        # Simulate processing time
        await asyncio.sleep(0.5)
        
        # Keywords to trigger specific responses
        user_lower = user_message.lower()
        
        if any(keyword in user_lower for keyword in ["xss", "cross-site scripting"]):
            return """Cross-Site Scripting (XSS) is a client-side vulnerability that occurs when an application includes untrusted data in a web page without proper validation or escaping. Here's a comprehensive analysis:

**Types of XSS:**
1. **Reflected XSS**: Payload is reflected back immediately
2. **Stored XSS**: Payload is stored and executed later
3. **DOM-based XSS**: Vulnerability exists in client-side code

**Common Payloads for Testing:**
- Basic: `<script>alert('XSS')</script>`
- Event handlers: `<img src=x onerror=alert('XSS')>`
- JavaScript: `<svg onload=alert('XSS')>`

**Prevention Measures:**
- Input validation and sanitization
- Content Security Policy (CSP)
- Output encoding
- Use security headers

**Ethical Testing Guidelines:**
- Only test on authorized targets
- Use non-destructive payloads
- Report vulnerabilities responsibly
- Document findings thoroughly

Would you like me to explain specific testing methodologies or prevention techniques?"""

        elif any(keyword in user_lower for keyword in ["sql injection", "sqli"]):
            return """SQL Injection occurs when user input is incorrectly filtered for escape characters embedded in SQL statements. Here's a detailed breakdown:

**Types of SQL Injection:**
1. **Error-based**: Uses database errors to extract information
2. **Union-based**: Uses UNION operator to retrieve data
3. **Boolean-based**: Uses true/false responses
4. **Time-based**: Uses delays to infer information

**Common Testing Payloads:**
- Basic: `' OR '1'='1`
- Union: `' UNION SELECT 1,2,3--`
- Time-based: `'; WAITFOR DELAY '00:00:05'--`

**Detection Methods:**
- Error messages analysis
- Response time variations
- Boolean-based inference
- Automated tools (SQLMap)

**Prevention:**
- Parameterized queries/prepared statements
- Input validation
- Least privilege principle
- WAF implementation

**Ethical Testing:**
- Always get proper authorization
- Use read-only operations when possible
- Avoid data modification/deletion
- Report findings immediately

Need specific guidance on testing methodology or mitigation strategies?"""

        elif any(keyword in user_lower for keyword in ["nmap", "port scan", "network scan"]):
            return """Nmap (Network Mapper) is a powerful network discovery and security auditing tool. Here's a comprehensive guide:

**Basic Nmap Commands:**
- Host discovery: `nmap -sn 192.168.1.0/24`
- TCP SYN scan: `nmap -sS target.com`
- Service detection: `nmap -sV target.com`
- OS detection: `nmap -O target.com`
- Aggressive scan: `nmap -A target.com`

**Stealth Techniques:**
- SYN scan: `nmap -sS` (default, stealthy)
- FIN scan: `nmap -sF` (bypass simple firewalls)
- Timing: `nmap -T2` (slower, more stealthy)

**Common Use Cases:**
- Network asset discovery
- Service enumeration
- Vulnerability assessment preparation
- Security posture evaluation

**Ethical Guidelines:**
- Only scan authorized networks
- Use appropriate timing to avoid DoS
- Respect rate limits and system resources
- Document all scanning activities
- Follow responsible disclosure

**Legal Considerations:**
- Obtain written permission before scanning
- Understand local laws and regulations
- Use only for legitimate security testing
- Maintain proper documentation

What specific scanning technique would you like to explore further?"""

        elif any(keyword in user_lower for keyword in ["bug bounty", "vulnerability research"]):
            return """Bug bounty hunting is a legitimate way to find and report security vulnerabilities. Here's a comprehensive methodology:

**Reconnaissance Phase:**
1. **Passive Information Gathering:**
   - Subdomain enumeration (Subfinder, Amass)
   - DNS reconnaissance (DNSrecon, Fierce)
   - OSINT gathering (Shodan, Google dorking)
   - Social media analysis

2. **Active Reconnaissance:**
   - Port scanning (Nmap)
   - Service enumeration
   - Technology stack identification
   - Directory brute-forcing

**Vulnerability Testing:**
- **Web Application Testing:**
  - OWASP Top 10 vulnerabilities
  - Business logic flaws
  - Authentication bypasses
  - Authorization issues

- **API Security Testing:**
  - Endpoint discovery
  - Authentication flaws
  - Rate limiting bypass
  - Data exposure

**Tools and Automation:**
- Burp Suite Professional
- OWASP ZAP
- Nuclei templates
- Custom scripts and tools

**Reporting Best Practices:**
1. Clear vulnerability description
2. Step-by-step reproduction
3. Impact assessment
4. Proof of concept (non-destructive)
5. Remediation suggestions

**Ethical Standards:**
- Follow program rules strictly
- Respect scope limitations
- Avoid data access/modification
- Report immediately upon discovery
- Maintain confidentiality

Which aspect of bug bounty hunting would you like to dive deeper into?"""

        else:
            return f"""I'm your ethical hacking and cybersecurity assistant. I can help you with:

**Core Areas:**
- Vulnerability research and analysis
- Penetration testing methodologies  
- Bug bounty hunting strategies
- Security tool usage and automation
- CVE analysis and exploitation
- Security report writing
- OWASP guidelines implementation

**Your Query:** "{user_message}"

I noticed you're asking about cybersecurity topics. To provide the most helpful response, could you specify:

1. **What type of security testing** are you planning?
2. **What tools or techniques** are you interested in?
3. **What's your experience level** with ethical hacking?
4. **Do you have proper authorization** for your testing activities?

**Important Reminders:**
- Always ensure you have explicit permission before testing
- Follow responsible disclosure practices
- Use knowledge for legitimate security research only
- Respect system resources and avoid disruption

How can I assist you with your ethical hacking and cybersecurity research today?"""

    async def _generate_mock_response(self, messages: List[Dict[str, str]], model_name: str) -> Dict[str, Any]:
        """Generate mock response when model loading fails."""
        return {
            "content": "I'm currently running in demo mode. Please ensure you have a compatible LLM model available in the models directory for full functionality. I can still help with cybersecurity guidance and methodologies!",
            "model": model_name,
            "tokens_used": 25,
            "finish_reason": "stop"
        }
    
    def list_available_models(self) -> List[str]:
        """List available models in the models directory."""
        try:
            if not self.models_path.exists():
                return []
            
            model_files = []
            for file_path in self.models_path.iterdir():
                if file_path.is_file() and file_path.suffix in ['.gguf', '.bin', '.safetensors']:
                    model_files.append(file_path.name)
            
            # Add default models if no files found
            if not model_files:
                model_files = ["demo-model.gguf", settings.default_model]
            
            return model_files
            
        except Exception as e:
            logger.error(f"Error listing models: {e}")
            return ["demo-model.gguf"]
    
    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific model."""
        return self.loaded_models.get(model_name)
    
    def unload_model(self, model_name: str) -> bool:
        """Unload a specific model."""
        if model_name in self.loaded_models:
            del self.loaded_models[model_name]
            if self.current_model == model_name:
                self.current_model = None
            logger.info(f"Model {model_name} unloaded")
            return True
        return False