#!/usr/bin/env python3
"""
Complete NVD CVE 2025 Cybersecurity System Frontend
Streamlit interface for the comprehensive NVD CVE dataset with LLaMA integration
"""

import streamlit as st
import requests
import json
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# --- Configuration ---
BACKEND_URL = "http://127.0.0.1:8000"

# --- Page Configuration ---
st.set_page_config(
    page_title="🛡️ Complete NVD CVE 2025 Cybersecurity Intelligence System",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Custom CSS styling
st.markdown("""
<style>
.main-header {
    background: linear-gradient(90deg, #1e40af 0%, #3b82f6 50%, #06b6d4 100%);
    padding: 2rem;
    border-radius: 15px;
    color: white;
    text-align: center;
    margin-bottom: 2rem;
    box-shadow: 0 10px 25px rgba(0,0,0,0.1);
}

.metric-card {
    background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
    padding: 1.5rem;
    border-radius: 12px;
    border-left: 5px solid #3b82f6;
    margin: 0.5rem 0;
    box-shadow: 0 4px 15px rgba(0,0,0,0.05);
}

.cve-card {
    background: #fef2f2;
    padding: 1.5rem;
    border-radius: 10px;
    border-left: 4px solid #dc2626;
    margin: 1rem 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}

.success-card {
    background: #f0fdf4;
    padding: 1.5rem;
    border-radius: 10px;
    border-left: 4px solid #16a34a;
    margin: 1rem 0;
}

.analysis-card {
    background: #fefce8;
    padding: 1.5rem;
    border-radius: 10px;
    border-left: 4px solid #eab308;
    margin: 1rem 0;
}

.sidebar-content {
    background: #f8fafc;
    padding: 1rem;
    border-radius: 10px;
    margin: 1rem 0;
}

.stButton > button {
    background: linear-gradient(90deg, #3b82f6 0%, #1d4ed8 100%);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0.75rem 1.5rem;
    font-weight: 600;
    transition: all 0.3s ease;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(59, 130, 246, 0.3);
}

.stTextInput > div > div > input {
    border-radius: 8px;
    border: 2px solid #e5e7eb;
    transition: border-color 0.3s ease;
}

.stTextInput > div > div > input:focus {
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}
</style>
""", unsafe_allow_html=True)

def check_backend_health():
    """Check if backend is healthy and return system info"""
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if response.status_code == 200:
            return True, response.json()
        return False, None
    except requests.RequestException:
        return False, None

def get_dataset_stats():
    """Get comprehensive dataset statistics"""
    try:
        response = requests.get(f"{BACKEND_URL}/complete-dataset-stats", timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None

def search_cves(query):
    """Search CVEs using the backend"""
    try:
        response = requests.post(
            f"{BACKEND_URL}/search-complete-cves",
            json={"text": query},
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None

def get_ai_response(question):
    """Get AI response using the complete training dataset"""
    try:
        response = requests.post(
            f"{BACKEND_URL}/chat",
            json={"text": question},
            timeout=30
        )
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Complete NVD CVE 2025 Cybersecurity Intelligence System</h1>
        <p>Comprehensive CVE Analysis with 100% NVD Dataset Coverage | LLaMA-Enhanced AI | 20,814+ CVEs | 60,893+ Training Examples</p>
    </div>
    """, unsafe_allow_html=True)

    # Check backend health
    health_status, health_data = check_backend_health()
    
    if not health_status:
        st.error("🚨 Backend service is not available. Please start the backend first.")
        st.stop()

    # Sidebar with system information
    with st.sidebar:
        st.markdown("## 🎛️ System Control Panel")
        
        if health_data:
            st.markdown(f"""
            <div class="sidebar-content">
                <h4>System Status</h4>
                <p><strong>Service:</strong> {health_data.get('service', 'Unknown')}</p>
                <p><strong>Version:</strong> {health_data.get('version', 'Unknown')}</p>
                <p><strong>Status:</strong> <span style="color: green;">✅ Healthy</span></p>
            </div>
            """, unsafe_allow_html=True)
            
            dataset_info = health_data.get('dataset_info', {})
            st.markdown(f"""
            <div class="sidebar-content">
                <h4>Dataset Information</h4>
                <p><strong>Training Examples:</strong> {dataset_info.get('complete_training_examples', 0):,}</p>
                <p><strong>CVE Entries:</strong> {dataset_info.get('complete_cve_entries', 0):,}</p>
                <p><strong>Categories:</strong> {dataset_info.get('vulnerability_categories', 0)}</p>
                <p><strong>LLaMA Available:</strong> {'✅' if dataset_info.get('llama_available') else '❌'}</p>
            </div>
            """, unsafe_allow_html=True)

        # System capabilities
        capabilities = health_data.get('capabilities', {}) if health_data else {}
        st.markdown("## 🚀 Capabilities")
        for capability, status in capabilities.items():
            icon = "✅" if status else "❌"
            st.markdown(f"{icon} {capability.replace('_', ' ').title()}")

    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🏠 Dashboard", "🔍 CVE Search", "🤖 AI Assistant", "📊 Analytics"])

    with tab1:
        st.markdown("## 📊 System Dashboard")
        
        # Get dataset statistics
        stats = get_dataset_stats()
        if stats:
            overview = stats.get('dataset_overview', {})
            
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown(f"""
                <div class="metric-card">
                    <h3 style="color: #3b82f6; margin: 0;">📋 Total CVEs</h3>
                    <h2 style="color: #1e40af; margin: 0.5rem 0;">{overview.get('total_cves', 0):,}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div class="metric-card">
                    <h3 style="color: #059669; margin: 0;">🎯 Training Examples</h3>
                    <h2 style="color: #047857; margin: 0.5rem 0;">{overview.get('total_training_examples', 0):,}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"""
                <div class="metric-card">
                    <h3 style="color: #dc2626; margin: 0;">🏷️ Categories</h3>
                    <h2 style="color: #b91c1c; margin: 0.5rem 0;">{overview.get('vulnerability_categories', 0)}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                st.markdown(f"""
                <div class="metric-card">
                    <h3 style="color: #7c3aed; margin: 0;">💯 Coverage</h3>
                    <h2 style="color: #6d28d9; margin: 0.5rem 0;">100%</h2>
                </div>
                """, unsafe_allow_html=True)

            # Vulnerability distribution chart
            st.markdown("### 📈 Vulnerability Distribution")
            vuln_dist = stats.get('vulnerability_distribution', {})
            if vuln_dist:
                df = pd.DataFrame(list(vuln_dist.items()), columns=['Category', 'Count'])
                df = df.sort_values('Count', ascending=False).head(10)
                
                fig = px.bar(df, x='Category', y='Count', 
                           title="Top 10 Vulnerability Categories",
                           color='Count',
                           color_continuous_scale='viridis')
                fig.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig, use_container_width=True)

            # Processing statistics
            processing_stats = overview.get('processing_stats', {})
            if processing_stats:
                st.markdown("### 🔧 Processing Statistics")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"""
                    <div class="analysis-card">
                        <h4>Processing Overview</h4>
                        <p><strong>Total Processed:</strong> {processing_stats.get('total_cves_processed', 0):,}</p>
                        <p><strong>Successful Conversions:</strong> {processing_stats.get('successful_conversions', 0):,}</p>
                        <p><strong>Skipped Entries:</strong> {processing_stats.get('skipped_entries', 0):,}</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    <div class="success-card">
                        <h4>Generation Results</h4>
                        <p><strong>Training Examples:</strong> {processing_stats.get('training_examples_generated', 0):,}</p>
                        <p><strong>Database Entries:</strong> {processing_stats.get('cve_database_entries', 0):,}</p>
                        <p><strong>Success Rate:</strong> {(processing_stats.get('successful_conversions', 0) / max(processing_stats.get('total_cves_processed', 1), 1) * 100):.1f}%</p>
                    </div>
                    """, unsafe_allow_html=True)

    with tab2:
        st.markdown("## 🔍 CVE Search & Analysis")
        
        search_query = st.text_input(
            "🔎 Search CVEs (by ID, description, category, or keywords):",
            placeholder="e.g., CVE-2024-1234, SQL injection, buffer overflow..."
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            search_button = st.button("🔍 Search CVEs", use_container_width=True)
        
        if search_button and search_query:
            with st.spinner("🔍 Searching comprehensive CVE database..."):
                results = search_cves(search_query)
                
                if results:
                    st.success(f"✅ Found {len(results.get('cves', []))} results")
                    
                    for cve in results.get('cves', []):
                        st.markdown(f"""
                        <div class="cve-card">
                            <h4 style="color: #dc2626; margin: 0 0 0.5rem 0;">🚨 {cve.get('cve_id', 'Unknown')}</h4>
                            <p><strong>Category:</strong> {cve.get('category', 'Unknown')}</p>
                            <p><strong>Severity:</strong> <span style="color: #dc2626;">{cve.get('severity', 'Unknown')}</span> | 
                               <strong>CVSS Score:</strong> {cve.get('cvss_score', 'N/A')}/10.0</p>
                            <p><strong>Description:</strong> {cve.get('description', 'No description available')[:300]}...</p>
                            <p><strong>Published:</strong> {cve.get('published', 'Unknown')}</p>
                            {f"<p><strong>CWEs:</strong> {', '.join(cve.get('cwes', []))}</p>" if cve.get('cwes') else ""}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("No CVEs found for your search query.")

    with tab3:
        st.markdown("## 🤖 AI Cybersecurity Assistant")
        st.markdown("Ask questions about cybersecurity, vulnerabilities, or specific CVEs. The AI is trained on the complete NVD 2025 dataset.")
        
        # Predefined example questions
        st.markdown("### 💡 Example Questions:")
        example_questions = [
            "What are the most critical vulnerabilities in 2025?",
            "Explain buffer overflow vulnerabilities and how to prevent them",
            "What is the difference between SQL injection and XSS?",
            "How do I assess the risk of a CVSS score of 8.5?",
            "What are the latest trends in cybersecurity threats?"
        ]
        
        for i, question in enumerate(example_questions):
            if st.button(f"💡 {question}", key=f"example_{i}"):
                st.session_state.ai_question = question

        # AI Question input
        ai_question = st.text_area(
            "🤖 Ask your cybersecurity question:",
            value=st.session_state.get('ai_question', ''),
            placeholder="e.g., How can I protect against injection attacks?",
            height=100
        )
        
        if st.button("🤖 Get AI Analysis", use_container_width=True):
            if ai_question:
                with st.spinner("🧠 AI is analyzing using complete NVD dataset..."):
                    ai_response = get_ai_response(ai_question)
                    
                    if ai_response:
                        st.markdown(f"""
                        <div class="analysis-card">
                            <h4>🤖 AI Analysis Response</h4>
                            <div style="white-space: pre-wrap;">{ai_response.get('response', 'No response available')}</div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Show additional information if available
                        col1, col2 = st.columns(2)
                        with col1:
                            if ai_response.get('confidence'):
                                st.info(f"**Confidence:** {ai_response['confidence']:.2f}")
                            if ai_response.get('domain'):
                                st.info(f"**Domain:** {ai_response['domain']}")
                        
                        with col2:
                            if ai_response.get('source'):
                                st.info(f"**Source:** {ai_response['source']}")
                            if ai_response.get('llama_response'):
                                st.success("✅ Enhanced with LLaMA")
                        
                        # Show matched CVEs if available
                        if ai_response.get('matched_cves'):
                            st.markdown("**🎯 Related CVEs:**")
                            for cve in ai_response['matched_cves'][:3]:  # Show top 3
                                st.markdown(f"- {cve}")
                    else:
                        st.error("❌ Failed to get AI response. Please try again.")
            else:
                st.warning("⚠️ Please enter a question first.")

    with tab4:
        st.markdown("## 📊 Advanced Analytics")
        
        stats = get_dataset_stats()
        if stats:
            # Top categories pie chart
            st.markdown("### 🥧 Vulnerability Categories Distribution")
            top_categories = stats.get('top_categories', {})
            if top_categories:
                df_pie = pd.DataFrame(list(top_categories.items()), columns=['Category', 'Count'])
                fig_pie = px.pie(df_pie, values='Count', names='Category', 
                               title="Distribution of Top Vulnerability Categories")
                st.plotly_chart(fig_pie, use_container_width=True)

            # Detailed statistics table
            st.markdown("### 📋 Detailed Statistics")
            vuln_dist = stats.get('vulnerability_distribution', {})
            if vuln_dist:
                df_table = pd.DataFrame(list(vuln_dist.items()), columns=['Category', 'Count'])
                df_table['Percentage'] = (df_table['Count'] / df_table['Count'].sum() * 100).round(2)
                df_table = df_table.sort_values('Count', ascending=False)
                st.dataframe(df_table, use_container_width=True)

            # System completeness indicator
            st.markdown(f"""
            <div class="success-card">
                <h3>✅ {stats.get('dataset_completeness', 'Dataset Status')}</h3>
                <p>This system provides comprehensive coverage of the entire NVD CVE 2025 dataset with advanced AI capabilities.</p>
            </div>
            """, unsafe_allow_html=True)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #6b7280; padding: 1rem;">
        🛡️ Complete NVD CVE 2025 Cybersecurity Intelligence System | 
        Powered by LLaMA & Comprehensive Dataset Processing | 
        Built with ❤️ for Cybersecurity Professionals
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
