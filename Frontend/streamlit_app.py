import streamlit as st
import requests
import json
from datetime import datetime
import time

# Page config
st.set_page_config(
    page_title="Cyber LLM RAG Search",
    page_icon="🔍",
    layout="wide"
)

# API endpoints
API_BASE = "http://localhost:8000"

def main():
    st.title("🔍 Cyber LLM RAG Search")
    st.markdown("*AI-Powered Cybersecurity Intelligence*")
    
    # Sidebar status
    with st.sidebar:
        st.header("🛠️ System Status")
        check_system_status()
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Search", "🚨 CVE Analysis", "📊 Stats"])
    
    with tab1:
        search_interface()
    
    with tab2:
        cve_analysis_interface()
    
    with tab3:
        stats_interface()

def check_system_status():
    """Check and display system status"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=5)
        if response.status_code == 200:
            st.success("✅ System Online")
            
            # Get system info
            info_response = requests.get(f"{API_BASE}/", timeout=5)
            if info_response.status_code == 200:
                info = info_response.json()
                st.metric("CVE Database", f"{info.get('cve_count', 0):,}")
                st.metric("Training Data", f"{info.get('training_count', 0):,}")
        else:
            st.error("❌ System Offline")
    except:
        st.error("❌ Cannot connect")

def search_interface():
    """RAG search interface"""
    st.header("🔍 Intelligent CVE Search")
    
    # Search form
    query = st.text_input(
        "Search Query:",
        placeholder="e.g., SQL injection, buffer overflow, remote code execution",
        help="Enter vulnerability types, technologies, or specific security issues"
    )
    
    col1, col2 = st.columns(2)
    with col1:
        include_web = st.checkbox("🌐 Include Web Search", value=True)
    with col2:
        max_results = st.selectbox("Max Results", [3, 5, 10], index=1)
    
    if st.button("🔍 Search", type="primary") and query.strip():
        perform_search(query.strip(), include_web, max_results)

def perform_search(query, include_web, max_results):
    """Perform the search and display results"""
    with st.spinner("🔍 Searching..."):
        try:
            # Call API
            response = requests.get(
                f"{API_BASE}/rag-search",
                params={
                    "query": query,
                    "include_web": include_web,
                    "max_results": max_results
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                display_search_results(data)
            else:
                st.error(f"❌ Search failed: {response.status_code}")
                
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

def display_search_results(data):
    """Display search results"""
    results = data.get('results', {})
    cve_results = results.get('cve_results', [])
    web_results = results.get('web_results', [])
    
    # Summary
    st.success(f"✅ Search completed at {datetime.now().strftime('%H:%M:%S')}")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("CVE Results", len(cve_results))
    with col2:
        st.metric("Web Results", len(web_results))
    with col3:
        st.metric("Total", len(cve_results) + len(web_results))
    
    # Display results
    if cve_results or web_results:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 CVE Database Results")
            if cve_results:
                for i, cve in enumerate(cve_results):
                    with st.expander(f"CVE {i+1}: {cve.get('cve_id', 'Unknown')} (Score: {cve.get('similarity_score', 0):.3f})"):
                        st.write(f"**Description:** {cve.get('description', 'N/A')}")
                        st.write(f"**Severity:** {cve.get('severity', 'Unknown')}")
                        st.write(f"**Category:** {cve.get('category', 'Unknown')}")
                        if cve.get('cvss_score'):
                            st.write(f"**CVSS Score:** {cve.get('cvss_score')}")
            else:
                st.info("No CVE results found")
        
        with col2:
            st.subheader("🌐 Web Results")
            if web_results:
                for i, web in enumerate(web_results):
                    with st.expander(f"Web {i+1}: {web.get('title', 'Unknown')[:50]}..."):
                        st.write(f"**Source:** {web.get('source', 'Unknown')}")
                        if web.get('url'):
                            st.write(f"**URL:** [Link]({web.get('url')})")
                        st.write(f"**Content:** {web.get('snippet', 'N/A')}")
            else:
                st.info("No web results found")
    else:
        st.warning("No results found. Try different search terms.")

def cve_analysis_interface():
    """CVE analysis interface"""
    st.header("🚨 CVE Analysis")
    
    cve_id = st.text_input(
        "CVE ID:",
        placeholder="e.g., CVE-2024-0001",
        help="Enter a specific CVE ID for detailed analysis"
    )
    
    if st.button("🔍 Analyze", type="primary") and cve_id.strip():
        analyze_cve(cve_id.strip())

def analyze_cve(cve_id):
    """Analyze specific CVE"""
    with st.spinner(f"🔍 Analyzing {cve_id}..."):
        try:
            response = requests.get(f"{API_BASE}/analyze-cve/{cve_id}", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                display_cve_analysis(data)
            elif response.status_code == 404:
                st.error(f"❌ CVE {cve_id} not found")
            else:
                st.error(f"❌ Analysis failed: {response.status_code}")
                
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

def display_cve_analysis(data):
    """Display CVE analysis results"""
    analysis = data.get('analysis', {})
    
    st.success(f"✅ Analysis completed for {analysis.get('cve_id', 'Unknown')}")
    
    # Main metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Severity", analysis.get('severity', 'Unknown'))
    with col2:
        st.metric("CVSS Score", analysis.get('cvss_score', 'N/A'))
    with col3:
        st.metric("Category", analysis.get('category', 'Unknown'))
    
    # Description
    st.subheader("📄 Description")
    st.write(analysis.get('description', 'No description available'))
    
    # Additional details
    if analysis.get('cwes'):
        st.subheader("🔧 CWE IDs")
        for cwe in analysis.get('cwes', []):
            st.text(f"• {cwe}")
    
    # Timeline
    col1, col2 = st.columns(2)
    with col1:
        if analysis.get('published'):
            st.write(f"**Published:** {analysis.get('published')[:10]}")
    with col2:
        if analysis.get('lastModified'):
            st.write(f"**Last Modified:** {analysis.get('lastModified')[:10]}")

def stats_interface():
    """Statistics interface"""
    st.header("📊 System Statistics")
    
    try:
        response = requests.get(f"{API_BASE}/stats", timeout=10)
        if response.status_code == 200:
            stats = response.json().get('stats', {})
            
            # Overview
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total CVEs", f"{stats.get('total_cves', 0):,}")
            with col2:
                st.metric("Training Examples", f"{stats.get('total_training_examples', 0):,}")
            with col3:
                st.metric("Categories", len(stats.get('categories', {})))
            with col4:
                st.metric("Severities", len(stats.get('severities', {})))
            
            # Categories
            if stats.get('categories'):
                st.subheader("🏷️ Top Categories")
                categories = list(stats['categories'].items())[:10]
                for cat, count in categories:
                    st.text(f"• {cat}: {count:,}")
            
            # Severities
            if stats.get('severities'):
                st.subheader("⚠️ Severity Distribution")
                for sev, count in stats['severities'].items():
                    st.text(f"• {sev}: {count:,}")
                    
        else:
            st.error("Failed to load statistics")
            
    except Exception as e:
        st.error(f"Error: {e}")

if __name__ == "__main__":
    main()
