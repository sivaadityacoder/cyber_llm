from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from pydantic import BaseModel
import uvicorn
import json
import os
import asyncio
from typing import Optional, Dict, List
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for data
complete_training_data = []
complete_cve_database = []
vulnerability_categories = {}
dataset_stats = {}
rag_system = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting RAG-Enhanced Cybersecurity System...")
    load_complete_dataset()
    await initialize_rag_system()
    
    logger.info("=" * 60)
    logger.info("🎉 RAG-ENHANCED CVE SYSTEM READY!")
    logger.info(f"📊 Training Examples: {len(complete_training_data):,}")
    logger.info(f"🚨 CVE Database: {len(complete_cve_database):,}")
    logger.info(f"🏷️  Categories: {len(vulnerability_categories)}")
    logger.info(f"🔍 RAG System: {'✅ Enabled' if rag_system else '❌ Disabled'}")
    logger.info(f"🌐 Web Search: ✅ Enabled (Free providers)")
    logger.info("=" * 60)
    yield
    # Shutdown
    logger.info("🔄 Shutting down RAG-Enhanced CVE System...")

app = FastAPI(
    title="RAG-Enhanced CVE Cyber LLM API", 
    description="Comprehensive cybersecurity AI assistant with RAG + Web Search capabilities",
    version="4.0.0",
    lifespan=lifespan
)

# Pydantic models
class Query(BaseModel):
    question: str
    max_results: Optional[int] = 5

class RAGQuery(BaseModel):
    query: str
    include_web: Optional[bool] = True
    max_results: Optional[int] = 5

class CVEAnalysisRequest(BaseModel):
    cve_id: str

async def initialize_rag_system():
    """Initialize the RAG system"""
    global rag_system
    try:
        # Import RAG system
        import sys
        sys.path.append('/home/siva/project/cyber_llm')
        from rag_web_integration import CyberSecurityRAG
        
        logger.info("🔍 Initializing RAG system...")
        rag_system = CyberSecurityRAG()
        logger.info("✅ RAG system initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize RAG system: {e}")
        rag_system = None

def load_complete_dataset():
    """Load the complete NVD CVE dataset"""
    global complete_training_data, complete_cve_database, vulnerability_categories, dataset_stats
    
    try:
        # Load complete CVE database
        cve_path = "/home/siva/project/cyber_llm/data/complete_nvd_cve_database.json"
        if os.path.exists(cve_path):
            with open(cve_path, 'r') as f:
                complete_cve_database = json.load(f)
            logger.info(f"✅ Loaded {len(complete_cve_database):,} CVE entries")
        
        # Load training data if available
        training_path = "/home/siva/project/cyber_llm/data/complete_nvd_cve_training_dataset.json"
        if os.path.exists(training_path):
            with open(training_path, 'r') as f:
                complete_training_data = json.load(f)
            logger.info(f"✅ Loaded {len(complete_training_data):,} training examples")
        
        # Generate vulnerability categories
        categories = {}
        for cve in complete_cve_database:
            category = cve.get('category', 'Unknown')
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        vulnerability_categories = dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))
        
        # Generate dataset stats
        severities = {}
        for cve in complete_cve_database:
            severity = cve.get('severity', 'Unknown')
            if severity not in severities:
                severities[severity] = 0
            severities[severity] += 1
        
        dataset_stats = {
            'total_cves': len(complete_cve_database),
            'total_training_examples': len(complete_training_data),
            'categories': vulnerability_categories,
            'severities': severities,
            'last_updated': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Error loading dataset: {e}")

@app.get("/")
async def root():
    """Root endpoint with system information"""
    return {
        "system": "RAG-Enhanced CVE Cyber LLM",
        "version": "4.0.0",
        "status": "operational",
        "features": {
            "cve_database": len(complete_cve_database),
            "training_examples": len(complete_training_data),
            "rag_enabled": rag_system is not None,
            "web_search": True,
            "real_time_intelligence": True
        },
        "endpoints": {
            "rag_search": "/rag-search",
            "cve_analysis": "/analyze-cve",
            "stats": "/stats",
            "categories": "/categories"
        }
    }

@app.get("/rag-search")
async def rag_search_endpoint(query: str, include_web: bool = True, max_results: int = 5):
    """RAG-powered search endpoint"""
    if not rag_system:
        raise HTTPException(status_code=503, detail="RAG system not available")
    
    try:
        logger.info(f"🔍 RAG search: {query}")
        results = await rag_system.hybrid_search(query, include_web=include_web)
        
        return {
            "status": "success",
            "query": query,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ RAG search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analyze-cve/{cve_id}")
async def analyze_cve(cve_id: str):
    """Analyze a specific CVE with RAG enhancement"""
    try:
        # Find CVE in database
        cve_data = None
        for cve in complete_cve_database:
            if cve.get('cve_id', '').upper() == cve_id.upper():
                cve_data = cve
                break
        
        if not cve_data:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        result = {
            "cve_id": cve_id,
            "analysis": cve_data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Add RAG enhancement if available
        if rag_system:
            try:
                rag_results = await rag_system.hybrid_search(
                    f"CVE {cve_id} {cve_data.get('description', '')}", 
                    include_web=True
                )
                result["rag_intelligence"] = {
                    "related_cves": rag_results.get('cve_results', [])[:3],
                    "web_intelligence": rag_results.get('web_results', [])[:3],
                    "summary": rag_results.get('summary', {})
                }
            except Exception as e:
                logger.warning(f"RAG enhancement failed: {e}")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ CVE analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/search")
async def search_cves(
    query: str, 
    category: Optional[str] = None, 
    severity: Optional[str] = None,
    limit: int = 10
):
    """Search CVEs with optional filters"""
    try:
        results = []
        query_lower = query.lower()
        
        for cve in complete_cve_database:
            # Text search
            if (query_lower in cve.get('description', '').lower() or 
                query_lower in cve.get('cve_id', '').lower() or
                query_lower in cve.get('title', '').lower()):
                
                # Apply filters
                if category and cve.get('category', '').lower() != category.lower():
                    continue
                if severity and cve.get('severity', '').lower() != severity.lower():
                    continue
                
                results.append(cve)
                
                if len(results) >= limit:
                    break
        
        return {
            "query": query,
            "filters": {"category": category, "severity": severity},
            "total_results": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    """Get system statistics"""
    return {
        "system": "RAG-Enhanced CVE System",
        "stats": dataset_stats,
        "rag_status": "enabled" if rag_system else "disabled",
        "uptime": datetime.now().isoformat()
    }

@app.get("/categories")
async def get_categories():
    """Get vulnerability categories"""
    return {
        "categories": vulnerability_categories,
        "total": len(vulnerability_categories)
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "systems": {
            "database": len(complete_cve_database) > 0,
            "rag": rag_system is not None,
            "api": True
        },
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
