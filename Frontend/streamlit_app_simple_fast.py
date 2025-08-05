#!/usr/bin/env python3
"""
Simple & Fast Cybersecurity AI Assistant
Minimal interface for quick responses
"""

import streamlit as st
import requests
import json

# Configuration
BACKEND_URL = "http://127.0.0.1:8000"

# Simple page config
st.set_page_config(
    page_title="🛡️ Cyber AI Assistant",
    layout="centered",
    page_icon="🛡️"
)

# Dark theme CSS for cybersecurity feel
st.markdown("""
<style>
/* Global dark theme */
.stApp {
    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0f0f0f 100%);
    color: #ffffff;
}

/* Hide Streamlit branding */
.stApp > header {
    background: transparent;
}

.stApp > header .st-emotion-cache-kgpedg {
    display: none;
}

/* Main header with cybersecurity gradient */
.main-header {
    background: linear-gradient(135deg, #000000 0%, #1e3a8a 30%, #3b1a8a 70%, #000000 100%);
    padding: 2rem;
    border-radius: 15px;
    color: #ffffff;
    text-align: center;
    margin-bottom: 2rem;
    box-shadow: 0 10px 30px rgba(59, 130, 246, 0.3);
    border: 1px solid #3b82f6;
}

.main-header h1 {
    margin: 0;
    font-size: 2.5rem;
    text-shadow: 0 0 20px rgba(59, 130, 246, 0.8);
}

/* Response box with dark theme */
.response-box {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
    padding: 1.5rem;
    border-radius: 12px;
    border-left: 4px solid #00ff88;
    margin: 1rem 0;
    box-shadow: 0 5px 20px rgba(0, 255, 136, 0.2);
    color: #ffffff;
    border: 1px solid #333333;
}

/* Error box with dark theme */
.error-box {
    background: linear-gradient(135deg, #2a1a1a 0%, #3a1a1a 100%);
    padding: 1.5rem;
    border-radius: 12px;
    border-left: 4px solid #ff4444;
    margin: 1rem 0;
    box-shadow: 0 5px 20px rgba(255, 68, 68, 0.2);
    color: #ffffff;
    border: 1px solid #444444;
}

/* Success box */
.success-box {
    background: linear-gradient(135deg, #1a2a1a 0%, #1a3a1a 100%);
    padding: 1.5rem;
    border-radius: 12px;
    border-left: 4px solid #00ff88;
    margin: 1rem 0;
    box-shadow: 0 5px 20px rgba(0, 255, 136, 0.2);
    color: #ffffff;
    border: 1px solid #335533;
}

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    background: #1a1a1a;
    border-radius: 10px;
    padding: 0.5rem;
}

.stTabs [data-baseweb="tab"] {
    background: #2a2a2a;
    color: #ffffff;
    border-radius: 8px;
    margin: 0 0.2rem;
    border: 1px solid #3b82f6;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%);
    color: #ffffff;
    box-shadow: 0 0 15px rgba(59, 130, 246, 0.5);
}

/* Button styling */
.stButton > button {
    background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 0.75rem 1.5rem;
    font-weight: 600;
    transition: all 0.3s ease;
    box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    border: 1px solid #3b82f6;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(59, 130, 246, 0.4);
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
}

/* Primary button */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
    color: #000000;
    box-shadow: 0 4px 15px rgba(0, 255, 136, 0.3);
    border: 1px solid #00ff88;
}

.stButton > button[kind="primary"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 255, 136, 0.4);
}

/* Input styling */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #2a2a2a;
    color: #ffffff;
    border: 2px solid #3b82f6;
    border-radius: 10px;
    transition: all 0.3s ease;
}

.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #00ff88;
    box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
}

/* Expander styling */
.streamlit-expanderHeader {
    background: #2a2a2a;
    color: #ffffff;
    border: 1px solid #3b82f6;
    border-radius: 10px;
}

.streamlit-expanderContent {
    background: #1a1a1a;
    border: 1px solid #333333;
    border-radius: 0 0 10px 10px;
}

/* Info boxes */
.stInfo {
    background: linear-gradient(135deg, #1a2a3a 0%, #2a3a4a 100%);
    border: 1px solid #3b82f6;
    border-radius: 10px;
}

.stSuccess {
    background: linear-gradient(135deg, #1a3a2a 0%, #2a4a3a 100%);
    border: 1px solid #00ff88;
    border-radius: 10px;
}

.stWarning {
    background: linear-gradient(135deg, #3a3a1a 0%, #4a4a2a 100%);
    border: 1px solid #ffaa00;
    border-radius: 10px;
}

/* Spinner */
.stSpinner {
    color: #00ff88 !important;
}

/* Footer styling */
div[data-testid="stMarkdownContainer"] p {
    color: #cccccc;
}

/* Sidebar */
.css-1d391kg {
    background: #1a1a1a;
}

/* Hide Streamlit menu */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

def check_backend():
    """Quick backend health check"""
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=3)
        return response.status_code == 200
    except:
        return False

def get_ai_response(question):
    """Get AI response"""
    try:
        response = requests.post(
            f"{BACKEND_URL}/chat",
            json={"text": question},
            timeout=20
        )
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def search_cves(query):
    """Search CVEs"""
    try:
        response = requests.post(
            f"{BACKEND_URL}/search-complete-cves",
            json={"text": query},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

# Main interface
st.markdown("""
<div class="main-header">
    <h1>🛡️ CYBERSECURITY AI COMMAND CENTER</h1>
    <p>🔒 Advanced Threat Intelligence | 20,814+ CVEs | AI-Powered Analysis 🔒</p>
</div>
""", unsafe_allow_html=True)

# Check backend status
if not check_backend():
    st.markdown("""
    <div class="error-box">
        ❌ <strong>Backend Offline</strong><br>
        Please start the backend service first.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# Main tabs
tab1, tab2 = st.tabs(["🤖 AI Chat", "🔍 CVE Search"])

with tab1:
    st.markdown("### 🤖 Ask the Cybersecurity AI")
    
    # Quick example buttons
    col1, col2 = st.columns(2)
    with col1:
        if st.button("💡 SQL Injection Info"):
            st.session_state.question = "What is SQL injection and how to prevent it?"
    with col2:
        if st.button("💡 Latest Threats 2025"):
            st.session_state.question = "What are the latest cybersecurity threats in 2025?"
    
    # Question input
    question = st.text_area(
        "Your question:",
        value=st.session_state.get('question', ''),
        placeholder="Ask about cybersecurity, vulnerabilities, or specific CVEs...",
        height=100
    )
    
    if st.button("🚀 Get Answer", type="primary"):
        if question:
            with st.spinner("🤖 AI is thinking..."):
                result = get_ai_response(question)
                
                if result:
                    st.markdown(f"""
                    <div class="response-box">
                        <strong>🤖 AI THREAT ANALYSIS:</strong><br><br>
                        {result.get('response', 'No response')}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Show metadata in columns
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.info(f"**Confidence:** {result.get('confidence', 0):.2f}")
                    with col2:
                        st.info(f"**Source:** {result.get('source', 'Unknown')}")
                    with col3:
                        if result.get('matched_cves'):
                            st.success(f"**Related CVEs:** {len(result['matched_cves'])}")
                else:
                    st.markdown("""
                    <div class="error-box">
                        ❌ <strong>Failed to get response</strong><br>
                        Please try again or simplify your question.
                    </div>
                    """, unsafe_allow_html=True)

with tab2:
    st.markdown("### 🔍 Search CVE Database")
    
    # Quick search buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔍 SQL Injection CVEs"):
            st.session_state.search = "SQL injection"
    with col2:
        if st.button("🔍 Buffer Overflow CVEs"):
            st.session_state.search = "buffer overflow"
    with col3:
        if st.button("🔍 2025 CVEs"):
            st.session_state.search = "CVE-2025"
    
    # Search input
    search_query = st.text_input(
        "Search CVEs:",
        value=st.session_state.get('search', ''),
        placeholder="e.g., CVE-2025-1234, SQL injection, buffer overflow..."
    )
    
    if st.button("🔍 Search", type="primary"):
        if search_query:
            with st.spinner("🔍 Searching CVE database..."):
                results = search_cves(search_query)
                
                if results and results.get('cves'):
                    st.markdown(f"""
                    <div class="success-box">
                        ✅ <strong>THREAT DATABASE SEARCH COMPLETE</strong><br>
                        Found {len(results['cves'])} matching vulnerabilities in the database.
                    </div>
                    """, unsafe_allow_html=True)
                    
                    for i, cve in enumerate(results['cves'][:5]):  # Show top 5
                        with st.expander(f"🚨 {cve.get('cve_id', 'Unknown')} - SEVERITY: {cve.get('severity', 'Unknown')}"):
                            st.markdown(f"""
                            **🏷️ Category:** {cve.get('category', 'Unknown')}  
                            **⚡ CVSS Score:** {cve.get('cvss_score', 'N/A')}/10.0  
                            **📝 Threat Description:** {cve.get('description', 'No description')[:200]}...  
                            **📅 Discovery Date:** {cve.get('published', 'Unknown')}
                            """)
                            if cve.get('cwes'):
                                st.markdown(f"**🔍 CWE Classifications:** {', '.join(cve['cwes'])}")
                else:
                    st.warning("❌ No CVEs found for your search.")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888888; padding: 1rem;">
    🛡️ <span style="color: #00ff88;">CYBERSECURITY COMMAND CENTER</span> 🛡️<br>
    <span style="color: #3b82f6;">Powered by Complete NVD 2025 Dataset | Advanced AI Threat Intelligence</span>
</div>
""", unsafe_allow_html=True)
