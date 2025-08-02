"""
RAG Retrieval system for knowledge base integration.
"""

import os
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from backend.config import settings

logger = logging.getLogger(__name__)


class Document:
    """Simple document class for RAG retrieval."""
    
    def __init__(self, page_content: str, metadata: Dict[str, Any]):
        self.page_content = page_content
        self.metadata = metadata


class RAGRetriever:
    """RAG retrieval system for cybersecurity knowledge."""
    
    def __init__(self):
        self.vector_db_path = Path(settings.vector_db_path)
        self.knowledge_base = self._load_knowledge_base()
        self._ensure_vector_db_directory()
    
    def _ensure_vector_db_directory(self):
        """Ensure vector database directory exists."""
        self.vector_db_path.mkdir(parents=True, exist_ok=True)
    
    def _load_knowledge_base(self) -> Dict[str, List[Document]]:
        """Load cybersecurity knowledge base."""
        knowledge_base = {
            "owasp_top10": self._load_owasp_knowledge(),
            "cve_database": self._load_cve_knowledge(),
            "payloads": self._load_payload_knowledge(),
            "nuclei_templates": self._load_nuclei_knowledge(),
            "methodologies": self._load_methodology_knowledge()
        }
        
        logger.info(f"Loaded knowledge base with {sum(len(docs) for docs in knowledge_base.values())} documents")
        return knowledge_base
    
    def _load_owasp_knowledge(self) -> List[Document]:
        """Load OWASP Top 10 knowledge."""
        owasp_data = [
            {
                "title": "A01:2021 – Broken Access Control",
                "content": """Broken Access Control occurs when users can act outside of their intended permissions. This can lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits.

Common vulnerabilities include:
- Violation of the principle of least privilege
- Bypassing access control checks by modifying the URL
- Elevation of privilege (acting as admin without being logged in)
- Metadata manipulation (JWT token replay/manipulation)
- CORS misconfiguration allowing API access from unauthorized origins

Testing methods:
- Parameter manipulation in URLs
- Direct object references testing
- Role-based access testing
- Privilege escalation attempts
- API endpoint enumeration""",
                "category": "owasp_top10",
                "severity": "high"
            },
            {
                "title": "A02:2021 – Cryptographic Failures",
                "content": """Cryptographic Failures occur when sensitive data is transmitted or stored without proper cryptographic protection. This includes weak encryption, improper key management, and transmission of data in cleartext.

Common issues:
- Transmitting or storing sensitive data in cleartext
- Using old or weak cryptographic algorithms
- Using default or weak encryption keys
- Improper certificate validation
- Missing encryption of sensitive data

Testing approaches:
- Traffic interception and analysis
- SSL/TLS configuration testing
- Weak cipher detection
- Certificate validation bypass
- Data encryption verification""",
                "category": "owasp_top10",
                "severity": "high"
            },
            {
                "title": "A03:2021 – Injection",
                "content": """Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Attackers can trick the interpreter into executing unintended commands or accessing data without authorization.

Types of injection attacks:
- SQL Injection (SQLi)
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection

Prevention measures:
- Use parameterized queries/prepared statements
- Input validation and sanitization
- Escape special characters
- Use allowlists for input validation
- Implement proper error handling""",
                "category": "owasp_top10",
                "severity": "critical"
            }
        ]
        
        return [
            Document(
                page_content=item["content"],
                metadata={
                    "source": "owasp_top10",
                    "title": item["title"],
                    "category": item["category"],
                    "severity": item["severity"]
                }
            )
            for item in owasp_data
        ]
    
    def _load_cve_knowledge(self) -> List[Document]:
        """Load CVE knowledge base."""
        cve_data = [
            {
                "cve_id": "CVE-2023-12345",
                "content": """Example critical vulnerability in web applications allowing remote code execution through improper input validation. This vulnerability affects multiple frameworks and requires immediate patching.

Impact: Remote Code Execution
CVSS Score: 9.8 (Critical)
Affected Systems: Web applications using vulnerable framework versions
Exploitation: Send specially crafted HTTP requests to trigger RCE
Mitigation: Update to latest framework version, implement input validation""",
                "severity": "critical",
                "category": "web_application"
            }
        ]
        
        return [
            Document(
                page_content=item["content"],
                metadata={
                    "source": "cve_database",
                    "cve_id": item["cve_id"],
                    "severity": item["severity"],
                    "category": item["category"]
                }
            )
            for item in cve_data
        ]
    
    def _load_payload_knowledge(self) -> List[Document]:
        """Load payload and exploit knowledge."""
        payload_data = [
            {
                "type": "xss",
                "content": """Cross-Site Scripting (XSS) Payloads:

Basic XSS:
- <script>alert('XSS')</script>
- <img src=x onerror=alert('XSS')>
- <svg onload=alert('XSS')>

Event Handler XSS:
- <input onfocus=alert('XSS') autofocus>
- <select onfocus=alert('XSS') autofocus>
- <textarea onfocus=alert('XSS') autofocus>

DOM-based XSS:
- javascript:alert('XSS')
- #<script>alert('XSS')</script>

Filter Bypass:
- <scr<script>ipt>alert('XSS')</script>
- %3Cscript%3Ealert('XSS')%3C/script%3E""",
                "category": "web_exploitation"
            },
            {
                "type": "sql_injection",
                "content": """SQL Injection Payloads:

Basic SQLi:
- ' OR '1'='1
- ' OR 1=1--
- admin'--
- admin'/*

Union-based:
- ' UNION SELECT 1,2,3--
- ' UNION SELECT null,username,password FROM users--

Boolean-based:
- ' AND 1=1--
- ' AND 1=2--

Time-based:
- '; WAITFOR DELAY '00:00:05'--
- ' AND SLEEP(5)--
- ' OR pg_sleep(5)--""",
                "category": "web_exploitation"
            }
        ]
        
        return [
            Document(
                page_content=item["content"],
                metadata={
                    "source": "payloads",
                    "type": item["type"],
                    "category": item["category"]
                }
            )
            for item in payload_data
        ]
    
    def _load_nuclei_knowledge(self) -> List[Document]:
        """Load Nuclei template knowledge."""
        nuclei_data = [
            {
                "template": "web-scan",
                "content": """Nuclei Web Application Scanning Templates:

Common vulnerabilities templates:
- technologies/ - Technology detection
- vulnerabilities/ - Known vulnerability checks  
- exposures/ - Information disclosure
- misconfiguration/ - Security misconfigurations
- takeovers/ - Subdomain takeover checks

Usage examples:
- nuclei -u target.com -t technologies/
- nuclei -u target.com -t vulnerabilities/
- nuclei -l targets.txt -t exposures/
- nuclei -u target.com -severity critical,high

Custom template structure:
- ID, info, requests, matchers
- HTTP methods: GET, POST, PUT, DELETE
- Matcher types: word, regex, status, size""",
                "category": "scanning"
            }
        ]
        
        return [
            Document(
                page_content=item["content"],
                metadata={
                    "source": "nuclei_templates",
                    "template": item["template"],
                    "category": item["category"]
                }
            )
            for item in nuclei_data
        ]
    
    def _load_methodology_knowledge(self) -> List[Document]:
        """Load ethical hacking methodologies."""
        methodology_data = [
            {
                "phase": "reconnaissance",
                "content": """Reconnaissance Phase in Ethical Hacking:

Passive Reconnaissance:
- OSINT gathering using public sources
- DNS enumeration (nslookup, dig, fierce)
- Subdomain discovery (Subfinder, Amass, Assetfinder)
- Search engine reconnaissance (Google dorking)
- Social media intelligence gathering
- Whois information gathering

Active Reconnaissance:  
- Port scanning (Nmap, Masscan)
- Service enumeration and banner grabbing
- Directory and file discovery (Dirb, Gobuster)
- Technology stack identification (Wappalyzer, BuiltWith)
- Network topology mapping

Tools and Techniques:
- Shodan for Internet-connected device discovery
- TheHarvester for email and subdomain gathering
- Recon-ng for comprehensive reconnaissance
- Maltego for link analysis and visualization""",
                "category": "methodology"
            }
        ]
        
        return [
            Document(
                page_content=item["content"],
                metadata={
                    "source": "methodologies",
                    "phase": item["phase"],
                    "category": item["category"]
                }
            )
            for item in methodology_data
        ]
    
    def retrieve(self, query: str, top_k: int = 5) -> List[Document]:
        """Retrieve relevant documents based on query."""
        try:
            # Simple keyword-based retrieval (replace with vector similarity in production)
            query_lower = query.lower()
            relevant_docs = []
            
            # Search through all knowledge base categories
            for category, documents in self.knowledge_base.items():
                for doc in documents:
                    # Calculate relevance score based on keyword matches
                    content_lower = doc.page_content.lower()
                    title_lower = doc.metadata.get("title", "").lower()
                    
                    score = 0
                    query_words = query_lower.split()
                    
                    for word in query_words:
                        if len(word) > 2:  # Skip very short words
                            if word in content_lower:
                                score += content_lower.count(word) * 2
                            if word in title_lower:
                                score += title_lower.count(word) * 3
                    
                    if score > 0:
                        relevant_docs.append((doc, score))
            
            # Sort by relevance score and return top_k
            relevant_docs.sort(key=lambda x: x[1], reverse=True)
            return [doc for doc, score in relevant_docs[:top_k]]
            
        except Exception as e:
            logger.error(f"RAG retrieval error: {e}")
            return []
    
    def add_document(self, content: str, metadata: Dict[str, Any]) -> bool:
        """Add a new document to the knowledge base."""
        try:
            category = metadata.get("category", "custom")
            if category not in self.knowledge_base:
                self.knowledge_base[category] = []
            
            doc = Document(page_content=content, metadata=metadata)
            self.knowledge_base[category].append(doc)
            
            logger.info(f"Added document to category: {category}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding document: {e}")
            return False
    
    def get_categories(self) -> List[str]:
        """Get list of available knowledge base categories."""
        return list(self.knowledge_base.keys())
    
    def get_document_count(self) -> Dict[str, int]:
        """Get document count by category."""
        return {
            category: len(documents) 
            for category, documents in self.knowledge_base.items()
        }