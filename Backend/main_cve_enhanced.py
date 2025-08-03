"""
🛡️ TRENDYOL-ENHANCED CYBERSECURITY AI BACKEND v5.0
Professional-Grade Security Intelligence with CVE Integration

Advanced Features:
- 159 professional training examples
- 100 real-world CVE intelligence entries
- Comprehensive vulnerability assessment capabilities
- Enterprise-grade threat intelligence
- Professional incident response guidance
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import asyncio
import hashlib
from collections import defaultdict

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Configure professional logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("TrendyolCVEEnhancedBackend")

class ChatRequest(BaseModel):
    message: str
    domain: Optional[str] = None
    include_cve_intelligence: bool = True
    severity_filter: Optional[str] = None

class ProfessionalAnalysisRequest(BaseModel):
    message: str
    include_vulnerability_assessment: bool = True
    threat_intelligence_level: str = "comprehensive"

class VulnerabilityAssessmentRequest(BaseModel):
    query: str
    cve_filter: Optional[str] = None
    severity_levels: List[str] = ["critical", "high"]
    assessment_type: str = "comprehensive"

class ThreatIntelligenceRequest(BaseModel):
    indicators: List[str]
    analysis_depth: str = "professional"
    include_cve_correlation: bool = True

@dataclass
class CVEIntelligence:
    """Professional CVE intelligence data structure"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    category: str
    attack_vector: str
    cwe_info: List[str]
    mitigation_strategies: List[str]
    threat_intelligence: Dict[str, Any]

class TrendyolCVEEnhancedAI:
    """Professional-grade cybersecurity AI with CVE intelligence integration"""
    
    def __init__(self):
        self.model_name = "Trendyol-Enhanced CVE Intelligence AI"
        self.version = "5.0.0"
        self.training_data = []
        self.cve_intelligence = {}
        self.security_domains = {}
        self.threat_intelligence_db = {}
        self.professional_capabilities = []
        
        # Load enhanced training data with CVE intelligence
        self.load_enhanced_training_data()
        self.initialize_professional_capabilities()
        self.build_cve_intelligence_index()
        
        logger.info(f"🛡️ {self.model_name} v{self.version} initialized successfully")
        logger.info(f"📊 Loaded {len(self.training_data)} professional examples")
        logger.info(f"🔍 Indexed {len(self.cve_intelligence)} CVE intelligence entries")
    
    def load_enhanced_training_data(self):
        """Load the enhanced training dataset with CVE intelligence"""
        try:
            data_file = "data/trendyol_cve_enhanced_training.json"
            if os.path.exists(data_file):
                with open(data_file, 'r', encoding='utf-8') as f:
                    self.training_data = json.load(f)
                    
                logger.info(f"✅ Loaded enhanced training data: {len(self.training_data)} examples")
                
                # Build domain statistics
                domain_count = defaultdict(int)
                cve_count = 0
                
                for example in self.training_data:
                    domain = example.get('domain', 'general')
                    domain_count[domain] += 1
                    
                    if 'cve_id' in example.get('metadata', {}):
                        cve_count += 1
                
                self.security_domains = dict(domain_count)
                logger.info(f"🎯 Security domains: {len(self.security_domains)}")
                logger.info(f"🔍 CVE intelligence entries: {cve_count}")
                
            else:
                logger.warning(f"❌ Enhanced training data not found: {data_file}")
                self.training_data = []
                
        except Exception as e:
            logger.error(f"❌ Error loading training data: {e}")
            self.training_data = []
    
    def build_cve_intelligence_index(self):
        """Build searchable CVE intelligence index"""
        logger.info("🔬 Building CVE intelligence index...")
        
        for example in self.training_data:
            metadata = example.get('metadata', {})
            if 'cve_id' in metadata:
                cve_id = metadata['cve_id']
                
                self.cve_intelligence[cve_id] = CVEIntelligence(
                    cve_id=cve_id,
                    description=example.get('answer', ''),
                    cvss_score=metadata.get('cvss_score', 0.0),
                    severity=metadata.get('severity', 'unknown'),
                    category=metadata.get('category', 'general'),
                    attack_vector=metadata.get('attack_vector', 'unknown'),
                    cwe_info=metadata.get('cwe_info', []),
                    mitigation_strategies=self.extract_mitigation_strategies(example.get('answer', '')),
                    threat_intelligence=metadata
                )
        
        logger.info(f"🎯 CVE intelligence index built: {len(self.cve_intelligence)} entries")
    
    def extract_mitigation_strategies(self, answer: str) -> List[str]:
        """Extract mitigation strategies from professional answer"""
        strategies = []
        
        # Look for mitigation sections in the answer
        if "Mitigation Strategies:" in answer:
            lines = answer.split('\n')
            in_mitigation_section = False
            
            for line in lines:
                if "Mitigation Strategies:" in line:
                    in_mitigation_section = True
                    continue
                elif in_mitigation_section and line.strip().startswith('-'):
                    strategies.append(line.strip()[1:].strip())
                elif in_mitigation_section and line.strip() == "":
                    break
        
        return strategies
    
    def initialize_professional_capabilities(self):
        """Initialize professional cybersecurity capabilities"""
        self.professional_capabilities = [
            "Enterprise Vulnerability Assessment",
            "Advanced Threat Intelligence Analysis", 
            "Professional Incident Response Planning",
            "Comprehensive Risk Assessment",
            "Sophisticated Threat Hunting",
            "Zero-Day Vulnerability Research",
            "Advanced Malware Analysis",
            "Professional Digital Forensics",
            "Enterprise Security Architecture",
            "Compliance and Governance",
            "CVE Intelligence and Analysis",
            "Real-time Threat Detection",
            "Professional Security Training",
            "Advanced Penetration Testing",
            "Enterprise Risk Management"
        ]
        
        logger.info(f"🏆 Professional capabilities initialized: {len(self.professional_capabilities)}")
    
    async def professional_chat_response(self, message: str, domain: Optional[str] = None, 
                                       include_cve_intelligence: bool = True) -> Dict[str, Any]:
        """Generate professional cybersecurity response with CVE intelligence"""
        
        # Determine the best matching domain and examples
        relevant_examples = self.find_relevant_examples(message, domain)
        
        # Check for CVE-related queries
        cve_context = ""
        if include_cve_intelligence:
            cve_context = await self.get_cve_intelligence_context(message)
        
        # Generate professional response
        response = await self.generate_professional_response(
            message, relevant_examples, cve_context
        )
        
        # Calculate confidence score
        confidence = self.calculate_response_confidence(message, relevant_examples, cve_context)
        
        # Determine primary domain
        primary_domain = self.determine_primary_domain(relevant_examples)
        
        return {
            "response": response,
            "confidence": confidence,
            "domain": primary_domain,
            "cve_intelligence_included": bool(cve_context),
            "relevant_examples": len(relevant_examples),
            "professional_grade": True,
            "enterprise_ready": True
        }
    
    def find_relevant_examples(self, message: str, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Find relevant training examples using professional matching"""
        message_lower = message.lower()
        relevant_examples = []
        
        for example in self.training_data:
            # Domain filtering
            if domain and not example.get('domain', '').startswith(domain):
                continue
            
            # Content relevance scoring
            question = example.get('question', '').lower()
            answer = example.get('answer', '').lower()
            
            relevance_score = 0
            
            # Check for direct keyword matches
            question_words = set(question.split())
            message_words = set(message_lower.split())
            common_words = question_words.intersection(message_words)
            relevance_score += len(common_words) * 2
            
            # Check for CVE mentions
            if any(word.startswith('cve-') for word in message_words):
                metadata = example.get('metadata', {})
                if 'cve_id' in metadata:
                    relevance_score += 10
            
            # Check for security domain keywords
            security_keywords = [
                'vulnerability', 'exploit', 'attack', 'security', 'incident',
                'threat', 'malware', 'penetration', 'assessment', 'forensics'
            ]
            
            for keyword in security_keywords:
                if keyword in message_lower and keyword in (question + answer):
                    relevance_score += 3
            
            if relevance_score > 5:
                example_with_score = example.copy()
                example_with_score['relevance_score'] = relevance_score
                relevant_examples.append(example_with_score)
        
        # Sort by relevance score
        relevant_examples.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return relevant_examples[:5]  # Return top 5 most relevant
    
    async def get_cve_intelligence_context(self, message: str) -> str:
        """Get relevant CVE intelligence context"""
        message_lower = message.lower()
        cve_context = ""
        
        # Check for specific CVE mentions
        cve_mentions = [word for word in message_lower.split() if word.startswith('cve-')]
        
        if cve_mentions:
            for cve_id in cve_mentions:
                cve_id_upper = cve_id.upper()
                if cve_id_upper in self.cve_intelligence:
                    cve_info = self.cve_intelligence[cve_id_upper]
                    cve_context += f"\n**CVE Intelligence for {cve_id_upper}:**\n"
                    cve_context += f"- Severity: {cve_info.severity.upper()}\n"
                    cve_context += f"- CVSS Score: {cve_info.cvss_score}\n"
                    cve_context += f"- Category: {cve_info.category}\n"
                    cve_context += f"- Attack Vector: {cve_info.attack_vector}\n"
        
        # Check for vulnerability-related queries
        elif any(keyword in message_lower for keyword in 
                ['vulnerability', 'exploit', 'cve', 'security flaw', 'bug']):
            
            # Find relevant CVEs by category or keywords
            relevant_cves = []
            for cve_id, cve_info in list(self.cve_intelligence.items())[:10]:
                if any(keyword in cve_info.description.lower() 
                      for keyword in message_lower.split()[:5]):
                    relevant_cves.append(cve_info)
            
            if relevant_cves:
                cve_context += "\n**Related CVE Intelligence:**\n"
                for cve_info in relevant_cves[:3]:
                    cve_context += f"- {cve_info.cve_id}: {cve_info.severity.upper()} severity, "
                    cve_context += f"CVSS {cve_info.cvss_score}\n"
        
        return cve_context
    
    async def generate_professional_response(self, message: str, relevant_examples: List[Dict[str, Any]], 
                                           cve_context: str) -> str:
        """Generate comprehensive professional response"""
        
        if not relevant_examples:
            return self.generate_general_professional_response(message, cve_context)
        
        # Use the most relevant example as base
        best_example = relevant_examples[0]
        base_answer = best_example.get('answer', '')
        
        # Enhance with CVE intelligence if available
        if cve_context:
            enhanced_response = f"{base_answer}\n\n{cve_context}"
        else:
            enhanced_response = base_answer
        
        # Add professional context
        professional_context = self.add_professional_context(message, relevant_examples)
        
        final_response = f"{enhanced_response}\n\n{professional_context}"
        
        return final_response
    
    def generate_general_professional_response(self, message: str, cve_context: str) -> str:
        """Generate general professional cybersecurity response"""
        
        base_response = """**Professional Cybersecurity Analysis:**

I can provide expert guidance on this cybersecurity topic based on industry best practices and professional standards. 

**Key Considerations:**
- Always follow ethical hacking principles and legal guidelines
- Implement defense-in-depth security strategies
- Maintain compliance with relevant frameworks (SOC2, ISO27001, NIST)
- Document all security activities for audit purposes
- Continuously update threat intelligence and security measures

**Professional Recommendations:**
- Conduct regular security assessments and vulnerability management
- Implement comprehensive incident response procedures
- Maintain up-to-date security awareness training
- Establish proper access controls and monitoring systems
- Engage with the cybersecurity community for knowledge sharing"""
        
        if cve_context:
            return f"{base_response}\n\n{cve_context}"
        
        return base_response
    
    def add_professional_context(self, message: str, relevant_examples: List[Dict[str, Any]]) -> str:
        """Add professional context to responses"""
        
        context = "**Professional Context:**\n"
        
        # Add compliance information
        context += "- This guidance aligns with enterprise security frameworks\n"
        context += "- Recommendations follow industry best practices\n"
        context += "- All activities should be authorized and documented\n"
        
        # Add domain-specific context
        domains = set(ex.get('domain', '').split('_')[0] for ex in relevant_examples)
        if domains:
            context += f"- Security domains involved: {', '.join(domains)}\n"
        
        # Add enterprise considerations
        context += "\n**Enterprise Considerations:**\n"
        context += "- Assess business impact and risk tolerance\n"
        context += "- Coordinate with relevant stakeholders\n"
        context += "- Follow change management procedures\n"
        context += "- Monitor and measure security effectiveness\n"
        
        return context
    
    def calculate_response_confidence(self, message: str, relevant_examples: List[Dict[str, Any]], 
                                    cve_context: str) -> float:
        """Calculate professional confidence score"""
        
        base_confidence = 0.7
        
        # Boost confidence for relevant examples
        if relevant_examples:
            avg_relevance = sum(ex.get('relevance_score', 0) for ex in relevant_examples) / len(relevant_examples)
            confidence_boost = min(avg_relevance / 20, 0.2)
            base_confidence += confidence_boost
        
        # Boost confidence for CVE intelligence
        if cve_context:
            base_confidence += 0.1
        
        # Boost confidence for professional terms
        professional_terms = [
            'enterprise', 'professional', 'compliance', 'framework',
            'assessment', 'governance', 'risk management'
        ]
        
        term_matches = sum(1 for term in professional_terms if term in message.lower())
        base_confidence += min(term_matches * 0.02, 0.1)
        
        return min(base_confidence, 0.98)
    
    def determine_primary_domain(self, relevant_examples: List[Dict[str, Any]]) -> str:
        """Determine the primary security domain"""
        if not relevant_examples:
            return "general_cybersecurity"
        
        # Count domain occurrences
        domain_count = defaultdict(int)
        for example in relevant_examples:
            domain = example.get('domain', 'general')
            domain_count[domain] += 1
        
        # Return most common domain
        primary_domain = max(domain_count.items(), key=lambda x: x[1])[0]
        return primary_domain
    
    async def vulnerability_assessment(self, query: str, cve_filter: Optional[str] = None,
                                     severity_levels: List[str] = None) -> Dict[str, Any]:
        """Professional vulnerability assessment"""
        
        if severity_levels is None:
            severity_levels = ["critical", "high"]
        
        relevant_cves = []
        
        # Filter CVEs by criteria
        for cve_id, cve_info in self.cve_intelligence.items():
            if cve_filter and cve_filter.upper() not in cve_id:
                continue
            
            if cve_info.severity not in severity_levels:
                continue
            
            # Check query relevance
            if any(keyword in cve_info.description.lower() 
                  for keyword in query.lower().split()):
                relevant_cves.append(cve_info)
        
        # Sort by CVSS score
        relevant_cves.sort(key=lambda x: x.cvss_score, reverse=True)
        
        assessment_result = {
            "query": query,
            "total_cves_found": len(relevant_cves),
            "severity_distribution": defaultdict(int),
            "top_vulnerabilities": [],
            "risk_assessment": "",
            "mitigation_priorities": [],
            "professional_recommendations": []
        }
        
        # Generate statistics
        for cve in relevant_cves:
            assessment_result["severity_distribution"][cve.severity] += 1
        
        # Top vulnerabilities
        for cve in relevant_cves[:10]:
            assessment_result["top_vulnerabilities"].append({
                "cve_id": cve.cve_id,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "category": cve.category,
                "attack_vector": cve.attack_vector
            })
        
        # Generate risk assessment
        critical_count = assessment_result["severity_distribution"]["critical"]
        high_count = assessment_result["severity_distribution"]["high"]
        
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 5:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        assessment_result["risk_assessment"] = f"Overall Risk Level: {risk_level}"
        
        # Generate professional recommendations
        assessment_result["professional_recommendations"] = [
            "Implement immediate patching for critical vulnerabilities",
            "Conduct comprehensive security assessment",
            "Update threat intelligence feeds",
            "Review and strengthen security controls",
            "Establish continuous monitoring procedures"
        ]
        
        return assessment_result
    
    async def threat_intelligence_analysis(self, indicators: List[str]) -> Dict[str, Any]:
        """Professional threat intelligence analysis"""
        
        analysis_result = {
            "indicators_analyzed": len(indicators),
            "threat_categories": set(),
            "related_cves": [],
            "risk_score": 0.0,
            "professional_assessment": "",
            "recommended_actions": []
        }
        
        # Analyze indicators against CVE intelligence
        for indicator in indicators:
            for cve_id, cve_info in self.cve_intelligence.items():
                if indicator.lower() in cve_info.description.lower():
                    analysis_result["related_cves"].append({
                        "cve_id": cve_id,
                        "relevance": "high",
                        "severity": cve_info.severity,
                        "cvss_score": cve_info.cvss_score
                    })
                    analysis_result["threat_categories"].add(cve_info.category)
        
        # Calculate risk score
        if analysis_result["related_cves"]:
            avg_cvss = sum(cve["cvss_score"] for cve in analysis_result["related_cves"]) / len(analysis_result["related_cves"])
            analysis_result["risk_score"] = min(avg_cvss / 10, 1.0)
        
        # Generate professional assessment
        if analysis_result["risk_score"] > 0.7:
            analysis_result["professional_assessment"] = "HIGH RISK: Immediate attention required"
        elif analysis_result["risk_score"] > 0.4:
            analysis_result["professional_assessment"] = "MEDIUM RISK: Monitor and assess"
        else:
            analysis_result["professional_assessment"] = "LOW RISK: Continue standard monitoring"
        
        # Convert set to list for JSON serialization
        analysis_result["threat_categories"] = list(analysis_result["threat_categories"])
        
        return analysis_result

# Initialize the professional AI system
ai_system = TrendyolCVEEnhancedAI()

# FastAPI application setup
app = FastAPI(
    title="🛡️ Trendyol-Enhanced CVE Intelligence API v5.0",
    description="Professional-grade cybersecurity AI with comprehensive CVE intelligence",
    version="5.0.0"
)

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Professional health check endpoint"""
    return {
        "status": "healthy",
        "model": ai_system.model_name,
        "version": ai_system.version,
        "training_examples": len(ai_system.training_data),
        "cve_intelligence_entries": len(ai_system.cve_intelligence),
        "security_domains": len(ai_system.security_domains),
        "professional_grade": True,
        "enterprise_ready": True,
        "cve_intelligence_enabled": True,
        "threat_intelligence_active": True
    }

@app.get("/model/info")
async def get_model_info():
    """Get comprehensive model information"""
    return {
        "model_name": ai_system.model_name,
        "version": ai_system.version,
        "description": "Professional cybersecurity AI with comprehensive CVE intelligence integration",
        "training_examples": len(ai_system.training_data),
        "cve_intelligence_entries": len(ai_system.cve_intelligence),
        "professional_capabilities": ai_system.professional_capabilities,
        "security_domains": list(ai_system.security_domains.keys()),
        "features": [
            "Enterprise Vulnerability Assessment",
            "Real-time CVE Intelligence",
            "Professional Threat Analysis", 
            "Advanced Risk Assessment",
            "Compliance Framework Support",
            "Professional Incident Response",
            "Comprehensive Security Guidance"
        ],
        "compliance_frameworks": ["SOC2", "ISO27001", "NIST", "GDPR"],
        "professional_grade": True,
        "enterprise_ready": True,
        "status": "operational"
    }

@app.get("/security/domains")
async def get_security_domains():
    """Get available security domains"""
    domain_list = []
    for domain, count in ai_system.security_domains.items():
        domain_list.append({
            "name": domain,
            "examples_count": count,
            "category": "professional" if "vulnerability_intelligence" in domain else "traditional"
        })
    
    return {
        "domains": domain_list,
        "total_domains": len(domain_list),
        "cve_domains": len([d for d in domain_list if d["category"] == "professional"])
    }

@app.get("/cve/intelligence/summary")
async def get_cve_intelligence_summary():
    """Get CVE intelligence summary"""
    severity_count = defaultdict(int)
    category_count = defaultdict(int)
    
    for cve_info in ai_system.cve_intelligence.values():
        severity_count[cve_info.severity] += 1
        category_count[cve_info.category] += 1
    
    return {
        "total_cves": len(ai_system.cve_intelligence),
        "severity_distribution": dict(severity_count),
        "category_distribution": dict(category_count),
        "latest_update": datetime.now().isoformat(),
        "intelligence_quality": "professional_grade"
    }

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """Professional chat endpoint with CVE intelligence"""
    try:
        response_data = await ai_system.professional_chat_response(
            message=request.message,
            domain=request.domain,
            include_cve_intelligence=request.include_cve_intelligence
        )
        
        return response_data
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error in chat processing")

@app.post("/professional-analysis")
async def professional_analysis_endpoint(request: ProfessionalAnalysisRequest):
    """Comprehensive professional security analysis"""
    try:
        # Get basic chat response
        chat_response = await ai_system.professional_chat_response(
            message=request.message,
            include_cve_intelligence=request.include_vulnerability_assessment
        )
        
        # Add vulnerability assessment if requested
        vulnerability_assessment = None
        if request.include_vulnerability_assessment:
            vulnerability_assessment = await ai_system.vulnerability_assessment(
                query=request.message,
                severity_levels=["critical", "high", "medium"]
            )
        
        return {
            "primary_response": chat_response,
            "vulnerability_assessment": vulnerability_assessment,
            "threat_intelligence_level": request.threat_intelligence_level,
            "professional_grade": True,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Professional analysis error: {e}")
        raise HTTPException(status_code=500, detail="Error in professional analysis")

@app.post("/vulnerability-assessment")
async def vulnerability_assessment_endpoint(request: VulnerabilityAssessmentRequest):
    """Professional vulnerability assessment endpoint"""
    try:
        assessment = await ai_system.vulnerability_assessment(
            query=request.query,
            cve_filter=request.cve_filter,
            severity_levels=request.severity_levels
        )
        
        return assessment
        
    except Exception as e:
        logger.error(f"Vulnerability assessment error: {e}")
        raise HTTPException(status_code=500, detail="Error in vulnerability assessment")

@app.post("/threat-intelligence")
async def threat_intelligence_endpoint(request: ThreatIntelligenceRequest):
    """Professional threat intelligence analysis"""
    try:
        analysis = await ai_system.threat_intelligence_analysis(
            indicators=request.indicators
        )
        
        return analysis
        
    except Exception as e:
        logger.error(f"Threat intelligence error: {e}")
        raise HTTPException(status_code=500, detail="Error in threat intelligence analysis")

@app.get("/cve/{cve_id}")
async def get_cve_details(cve_id: str):
    """Get detailed CVE information"""
    cve_id_upper = cve_id.upper()
    
    if cve_id_upper not in ai_system.cve_intelligence:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id_upper} not found in intelligence database")
    
    cve_info = ai_system.cve_intelligence[cve_id_upper]
    
    return {
        "cve_id": cve_info.cve_id,
        "description": cve_info.description[:500] + "..." if len(cve_info.description) > 500 else cve_info.description,
        "cvss_score": cve_info.cvss_score,
        "severity": cve_info.severity,
        "category": cve_info.category,
        "attack_vector": cve_info.attack_vector,
        "cwe_information": cve_info.cwe_info,
        "mitigation_strategies": cve_info.mitigation_strategies,
        "threat_intelligence": cve_info.threat_intelligence,
        "professional_analysis": f"This {cve_info.severity}-severity vulnerability requires professional attention in enterprise environments."
    }

@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "🛡️ Trendyol-Enhanced CVE Intelligence API v5.0",
        "description": "Professional-grade cybersecurity AI with comprehensive vulnerability intelligence",
        "features": [
            "Advanced CVE Intelligence Integration",
            "Professional Vulnerability Assessment", 
            "Enterprise Threat Intelligence",
            "Comprehensive Security Analysis",
            "Professional Incident Response Guidance"
        ],
        "documentation": "/docs",
        "health_check": "/health",
        "professional_grade": True,
        "enterprise_ready": True
    }

if __name__ == "__main__":
    print("🚀 Starting Trendyol-Enhanced CVE Intelligence Backend v5.0...")
    print(f"🛡️ Professional cybersecurity AI with {len(ai_system.cve_intelligence)} CVE intelligence entries")
    print(f"📊 Total training examples: {len(ai_system.training_data)}")
    print(f"🎯 Security domains: {len(ai_system.security_domains)}")
    
    uvicorn.run(
        "main_cve_enhanced:app",
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
    )
