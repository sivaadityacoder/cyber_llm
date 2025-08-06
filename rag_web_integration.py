"""
RAG + Web Search Integration for Cyber LLM
Combines local CVE dataset with real-time web search for comprehensive cybersecurity intelligence
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import aiohttp
import requests
from bs4 import BeautifulSoup
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import pickle
from urllib.parse import quote_plus, urljoin
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebSearchProvider:
    """Free web search using multiple providers"""
    
    def __init__(self):
        self.session = None
        self.search_engines = {
            'duckduckgo': self._search_duckduckgo,
            'searx': self._search_searx,
            'bing': self._search_bing_free
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search across multiple free providers"""
        all_results = []
        
        for engine_name, search_func in self.search_engines.items():
            try:
                logger.info(f"Searching with {engine_name} for: {query}")
                results = await search_func(query, max_results)
                if results:
                    all_results.extend(results)
                    logger.info(f"Found {len(results)} results from {engine_name}")
            except Exception as e:
                logger.warning(f"Error with {engine_name}: {e}")
                continue
        
        # Deduplicate and rank results
        unique_results = self._deduplicate_results(all_results)
        return unique_results[:max_results]
    
    async def _search_duckduckgo(self, query: str, max_results: int) -> List[Dict]:
        """Search using DuckDuckGo (free, no API key required)"""
        try:
            # DuckDuckGo instant answer API
            url = "https://api.duckduckgo.com/"
            params = {
                'q': query,
                'format': 'json',
                'no_html': '1',
                'skip_disambig': '1'
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    results = []
                    
                    # Abstract result
                    if data.get('Abstract'):
                        results.append({
                            'title': data.get('AbstractText', '')[:100],
                            'url': data.get('AbstractURL', ''),
                            'snippet': data.get('Abstract', ''),
                            'source': 'duckduckgo_instant'
                        })
                    
                    # Related topics
                    for topic in data.get('RelatedTopics', [])[:max_results-1]:
                        if isinstance(topic, dict) and 'Text' in topic:
                            results.append({
                                'title': topic.get('Text', '')[:100],
                                'url': topic.get('FirstURL', ''),
                                'snippet': topic.get('Text', ''),
                                'source': 'duckduckgo_related'
                            })
                    
                    return results
        except Exception as e:
            logger.error(f"DuckDuckGo search error: {e}")
        
        return []
    
    async def _search_searx(self, query: str, max_results: int) -> List[Dict]:
        """Search using public SearX instances"""
        searx_instances = [
            "https://searx.be",
            "https://search.sapti.me",
            "https://searx.prvcy.eu"
        ]
        
        for instance in searx_instances:
            try:
                url = f"{instance}/search"
                params = {
                    'q': query,
                    'format': 'json',
                    'categories': 'general'
                }
                
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = []
                        
                        for result in data.get('results', [])[:max_results]:
                            results.append({
                                'title': result.get('title', ''),
                                'url': result.get('url', ''),
                                'snippet': result.get('content', ''),
                                'source': f'searx_{instance.split("//")[1]}'
                            })
                        
                        if results:
                            return results
            except Exception as e:
                logger.warning(f"SearX instance {instance} error: {e}")
                continue
        
        return []
    
    async def _search_bing_free(self, query: str, max_results: int) -> List[Dict]:
        """Search using Bing web scraping (no API key)"""
        try:
            url = "https://www.bing.com/search"
            params = {
                'q': query + " cybersecurity vulnerability",
                'count': max_results,
                'mkt': 'en-US'
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    results = []
                    
                    # Parse Bing search results
                    for result in soup.find_all('li', class_='b_algo')[:max_results]:
                        title_elem = result.find('h2')
                        snippet_elem = result.find('p')
                        
                        if title_elem and snippet_elem:
                            title = title_elem.get_text().strip()
                            url = title_elem.find('a')['href'] if title_elem.find('a') else ''
                            snippet = snippet_elem.get_text().strip()
                            
                            results.append({
                                'title': title,
                                'url': url,
                                'snippet': snippet,
                                'source': 'bing_scraping'
                            })
                    
                    return results
        except Exception as e:
            logger.error(f"Bing search error: {e}")
        
        return []
    
    def _deduplicate_results(self, results: List[Dict]) -> List[Dict]:
        """Remove duplicate results based on URL and title similarity"""
        seen_urls = set()
        unique_results = []
        
        for result in results:
            url = result.get('url', '')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
        
        return unique_results

class CyberSecurityRAG:
    """RAG system combining local CVE database with web search"""
    
    def __init__(self, cve_data_path: str = "/home/siva/project/cyber_llm/data/complete_nvd_cve_database.json"):
        self.cve_data_path = cve_data_path
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # Lightweight, fast model
        self.index = None
        self.cve_documents = []
        self.web_search = None
        self.cache = {}
        self.cache_file = "rag_cache.pkl"
        
        # Load cache
        self._load_cache()
        
        # Initialize CVE database
        self._load_cve_database()
        self._build_vector_index()
    
    def _load_cache(self):
        """Load search cache to avoid repeated queries"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.cache = pickle.load(f)
                logger.info(f"Loaded {len(self.cache)} cached searches")
        except Exception as e:
            logger.warning(f"Cache loading error: {e}")
            self.cache = {}
    
    def _save_cache(self):
        """Save search cache"""
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except Exception as e:
            logger.warning(f"Cache saving error: {e}")
    
    def _load_cve_database(self):
        """Load and process CVE database for RAG"""
        try:
            with open(self.cve_data_path, 'r') as f:
                cve_data = json.load(f)
            
            logger.info(f"Loaded {len(cve_data)} CVE entries")
            
            # Process CVE data into documents
            # Handle both list and dict formats
            if isinstance(cve_data, list):
                # Data is a list of CVE objects
                for cve_info in cve_data:
                    if isinstance(cve_info, dict) and 'cve_id' in cve_info:
                        document = {
                            'id': cve_info['cve_id'],
                            'text': f"CVE {cve_info['cve_id']}: {cve_info.get('description', '')} "
                                   f"Severity: {cve_info.get('severity', 'Unknown')} "
                                   f"Category: {cve_info.get('category', 'Unknown')} "
                                   f"CVSS: {cve_info.get('cvss_score', 'N/A')}",
                            'metadata': cve_info,
                            'type': 'cve'
                        }
                        self.cve_documents.append(document)
            elif isinstance(cve_data, dict):
                # Data is a dict with CVE IDs as keys
                for cve_id, cve_info in cve_data.items():
                    document = {
                        'id': cve_id,
                        'text': f"CVE {cve_id}: {cve_info.get('description', '')} "
                               f"Severity: {cve_info.get('severity', 'Unknown')} "
                               f"Category: {cve_info.get('category', 'Unknown')} "
                               f"CVSS: {cve_info.get('cvss_score', 'N/A')}",
                        'metadata': cve_info,
                        'type': 'cve'
                    }
                    self.cve_documents.append(document)
            
            logger.info(f"Processed {len(self.cve_documents)} CVE documents")
            
        except Exception as e:
            logger.error(f"Error loading CVE database: {e}")
            self.cve_documents = []
    
    def _build_vector_index(self):
        """Build FAISS vector index for fast similarity search"""
        if not self.cve_documents:
            logger.warning("No CVE documents to index")
            return
        
        try:
            # Extract texts for embedding
            texts = [doc['text'] for doc in self.cve_documents]
            
            # Generate embeddings
            logger.info("Generating embeddings for CVE documents...")
            embeddings = self.model.encode(texts, show_progress_bar=True)
            
            # Build FAISS index
            dimension = embeddings.shape[1]
            self.index = faiss.IndexFlatIP(dimension)  # Inner product for cosine similarity
            
            # Normalize embeddings for cosine similarity
            faiss.normalize_L2(embeddings)
            self.index.add(embeddings.astype('float32'))
            
            logger.info(f"Built FAISS index with {self.index.ntotal} vectors")
            
        except Exception as e:
            logger.error(f"Error building vector index: {e}")
            self.index = None
    
    async def search_similar_cves(self, query: str, top_k: int = 5) -> List[Dict]:
        """Search for similar CVEs using vector similarity"""
        if not self.index or not self.cve_documents:
            return []
        
        try:
            # Encode query
            query_embedding = self.model.encode([query])
            faiss.normalize_L2(query_embedding)
            
            # Search
            scores, indices = self.index.search(query_embedding.astype('float32'), top_k)
            
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.cve_documents):
                    doc = self.cve_documents[idx]
                    results.append({
                        'cve_id': doc['id'],
                        'description': doc['metadata'].get('description', ''),
                        'severity': doc['metadata'].get('severity', ''),
                        'category': doc['metadata'].get('category', ''),
                        'cvss_score': doc['metadata'].get('cvss_score', ''),
                        'similarity_score': float(score),
                        'source': 'local_cve_database'
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []
    
    async def web_search_cybersecurity(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search web for cybersecurity information"""
        # Check cache first
        cache_key = f"web_{query.lower()}"
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if time.time() - cached_result['timestamp'] < 3600:  # 1 hour cache
                logger.info("Returning cached web search results")
                return cached_result['results']
        
        # Enhance query for cybersecurity context
        enhanced_query = f"{query} cybersecurity vulnerability CVE"
        
        async with WebSearchProvider() as search_provider:
            results = await search_provider.search(enhanced_query, max_results)
            
            # Process and enrich results
            processed_results = []
            for result in results:
                processed_result = {
                    'title': result.get('title', ''),
                    'url': result.get('url', ''),
                    'snippet': result.get('snippet', ''),
                    'source': f"web_{result.get('source', 'unknown')}",
                    'relevance_score': self._calculate_relevance(query, result),
                    'timestamp': datetime.now().isoformat()
                }
                processed_results.append(processed_result)
            
            # Cache results
            self.cache[cache_key] = {
                'results': processed_results,
                'timestamp': time.time()
            }
            self._save_cache()
            
            return processed_results
    
    def _calculate_relevance(self, query: str, result: Dict) -> float:
        """Calculate relevance score for web search results"""
        try:
            # Simple relevance scoring based on keyword overlap
            query_words = set(query.lower().split())
            result_text = f"{result.get('title', '')} {result.get('snippet', '')}".lower()
            result_words = set(result_text.split())
            
            # Jaccard similarity
            intersection = len(query_words.intersection(result_words))
            union = len(query_words.union(result_words))
            
            if union == 0:
                return 0.0
            
            base_score = intersection / union
            
            # Bonus for cybersecurity keywords
            cyber_keywords = {'vulnerability', 'cve', 'security', 'exploit', 'malware', 'threat'}
            cyber_bonus = len(cyber_keywords.intersection(result_words)) * 0.1
            
            return min(base_score + cyber_bonus, 1.0)
            
        except Exception:
            return 0.5  # Default relevance
    
    async def hybrid_search(self, query: str, include_web: bool = True) -> Dict:
        """Perform hybrid search combining local CVE data and web search"""
        logger.info(f"Performing hybrid search for: {query}")
        
        # Search local CVE database
        cve_results = await self.search_similar_cves(query, top_k=5)
        
        # Search web if requested
        web_results = []
        if include_web:
            web_results = await self.web_search_cybersecurity(query, max_results=5)
        
        # Combine and rank results
        combined_results = {
            'query': query,
            'timestamp': datetime.now().isoformat(),
            'cve_results': cve_results,
            'web_results': web_results,
            'summary': self._generate_search_summary(query, cve_results, web_results)
        }
        
        logger.info(f"Found {len(cve_results)} CVE results and {len(web_results)} web results")
        
        return combined_results
    
    def _generate_search_summary(self, query: str, cve_results: List[Dict], web_results: List[Dict]) -> Dict:
        """Generate a summary of search results"""
        summary = {
            'total_cve_matches': len(cve_results),
            'total_web_results': len(web_results),
            'top_categories': [],
            'severity_distribution': {},
            'key_insights': []
        }
        
        # Analyze CVE results
        if cve_results:
            categories = {}
            severities = {}
            
            for cve in cve_results:
                # Count categories
                category = cve.get('category', 'Unknown')
                categories[category] = categories.get(category, 0) + 1
                
                # Count severities
                severity = cve.get('severity', 'Unknown')
                severities[severity] = severities.get(severity, 0) + 1
            
            summary['top_categories'] = sorted(categories.items(), key=lambda x: x[1], reverse=True)
            summary['severity_distribution'] = severities
        
        # Generate insights
        if cve_results:
            high_severity_count = sum(1 for cve in cve_results if cve.get('severity') in ['HIGH', 'CRITICAL'])
            if high_severity_count > 0:
                summary['key_insights'].append(f"Found {high_severity_count} high/critical severity vulnerabilities")
        
        if web_results:
            summary['key_insights'].append(f"Found {len(web_results)} recent web sources for additional context")
        
        return summary

# FastAPI integration functions
async def initialize_rag_system():
    """Initialize the RAG system"""
    global rag_system
    rag_system = CyberSecurityRAG()
    logger.info("RAG system initialized successfully")

async def perform_rag_search(query: str, include_web: bool = True) -> Dict:
    """Perform RAG search and return results"""
    if 'rag_system' not in globals():
        await initialize_rag_system()
    
    return await rag_system.hybrid_search(query, include_web)

# Example usage
async def main():
    """Example usage of the RAG system"""
    rag = CyberSecurityRAG()
    
    test_queries = [
        "SQL injection vulnerabilities",
        "CVE-2024-0001",
        "buffer overflow prevention",
        "OWASP Top 10 vulnerabilities",
        "remote code execution attacks"
    ]
    
    for query in test_queries:
        print(f"\n{'='*50}")
        print(f"Query: {query}")
        print('='*50)
        
        results = await rag.hybrid_search(query)
        
        print(f"CVE Results: {len(results['cve_results'])}")
        for cve in results['cve_results'][:3]:
            print(f"  - {cve['cve_id']}: {cve['description'][:100]}...")
        
        print(f"\nWeb Results: {len(results['web_results'])}")
        for web in results['web_results'][:3]:
            print(f"  - {web['title'][:50]}... (Score: {web['relevance_score']:.2f})")
        
        print(f"\nSummary: {results['summary']}")

if __name__ == "__main__":
    asyncio.run(main())
