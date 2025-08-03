import streamlit as st
import requests
import time
import json
import os

# --- Configuration ---
BACKEND_URL = "http://127.0.0.1:8000"

# --- UI Setup ---
st.set_page_config(
    page_title="🛡️ Trendyol-Enhanced Cybersecurity AI v5.0 with CVE Intelligence", 
    layout="wide",
    page_icon="🛡️"
)

# Custom CSS for professional styling
st.markdown("""
<style>
.cve-header {
    background: linear-gradient(90deg, #dc2626 0%, #b91c1c 100%);
    padding: 1rem;
    border-radius: 10px;
    color: white;
    text-align: center;
    margin-bottom: 1rem;
}
.cve-card {
    background: #fef2f2;
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #dc2626;
    margin: 0.5rem 0;
}
.severity-critical { color: #dc2626; font-weight: bold; }
.severity-high { color: #ea580c; font-weight: bold; }
.severity-medium { color: #d97706; font-weight: bold; }
.severity-low { color: #65a30d; font-weight: bold; }
.vulnerability-metric {
    background: #f8fafc;
    padding: 0.5rem;
    border-radius: 4px;
    margin: 0.25rem 0;
    border-left: 3px solid #3b82f6;
}
</style>
""", unsafe_allow_html=True)

# Professional Header with CVE Integration
st.markdown("""
<div class="cve-header">
    <h1>🛡️ Trendyol-Enhanced Cybersecurity AI v5.0</h1>
    <h2>Professional Security Intelligence with CVE Integration</h2>
    <h3>Comprehensive Vulnerability Assessment & Threat Intelligence</h3>
    <p><em>Now featuring 100+ CVE intelligence entries from NVD 2025 dataset</em></p>
</div>
""", unsafe_allow_html=True)

# CVE Intelligence Features
st.info("🆕 **CVE Intelligence Features**: Real-time vulnerability assessment • CVSS scoring • Professional risk analysis • Threat intelligence correlation • Enterprise-grade security guidance")

# --- Session State Initialization ---
if "messages" not in st.session_state:
    st.session_state.messages = []

if "cve_filter" not in st.session_state:
    st.session_state.cve_filter = ""

# --- Functions ---
def check_backend_connection():
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        return response.status_code == 200, response.json()
    except:
        return False, {}

def get_model_info():
    try:
        response = requests.get(f"{BACKEND_URL}/model/info", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {"model_name": "Unknown", "status": "unavailable"}

def load_cve_intelligence_data():
    """Load local CVE intelligence data"""
    try:
        data_file = "/home/coder/startup/ownllm/data/trendyol_cve_enhanced_training.json"
        if os.path.exists(data_file):
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract CVE-specific entries
            cve_entries = []
            for entry in data:
                metadata = entry.get('metadata', {})
                if 'cve_id' in metadata:
                    cve_entries.append({
                        'cve_id': metadata['cve_id'],
                        'severity': metadata.get('severity', 'unknown'),
                        'cvss_score': metadata.get('cvss_score', 0.0),
                        'category': metadata.get('category', 'general'),
                        'attack_vector': metadata.get('attack_vector', 'unknown'),
                        'description': entry.get('answer', '')[:200] + "..."
                    })
            
            return cve_entries
    except Exception as e:
        st.error(f"Error loading CVE data: {e}")
    
    return []

def send_message(message, domain=None):
    try:
        payload = {"message": message}
        if domain:
            payload["domain"] = domain
            
        response = requests.post(
            f"{BACKEND_URL}/chat",
            json=payload,
            timeout=20
        )
        if response.status_code == 200:
            data = response.json()
            return data["response"], data.get("confidence", 0.0), data.get("domain", "general")
        else:
            return "Error: Failed to get response from backend", 0.0, "error"
    except Exception as e:
        return f"Error: {str(e)}", 0.0, "error"

def vulnerability_assessment(query, severity_filter=None):
    """Simulate vulnerability assessment using local CVE data"""
    cve_data = load_cve_intelligence_data()
    
    if not cve_data:
        return {"error": "CVE intelligence data not available"}
    
    # Filter by severity if specified
    if severity_filter and severity_filter != "all":
        cve_data = [cve for cve in cve_data if cve['severity'] == severity_filter]
    
    # Search for relevant CVEs
    query_lower = query.lower()
    relevant_cves = []
    
    for cve in cve_data:
        if any(keyword in cve['description'].lower() for keyword in query_lower.split()):
            relevant_cves.append(cve)
    
    # Sort by CVSS score
    relevant_cves.sort(key=lambda x: x['cvss_score'], reverse=True)
    
    return {
        "total_cves": len(relevant_cves),
        "query": query,
        "top_vulnerabilities": relevant_cves[:10],
        "severity_distribution": {
            "critical": len([c for c in relevant_cves if c['severity'] == 'critical']),
            "high": len([c for c in relevant_cves if c['severity'] == 'high']),
            "medium": len([c for c in relevant_cves if c['severity'] == 'medium']),
            "low": len([c for c in relevant_cves if c['severity'] == 'low'])
        }
    }

# --- Sidebar ---
with st.sidebar:
    st.header("🔧 System Status")
    
    # Backend Connection Status
    is_connected, health_data = check_backend_connection()
    if is_connected:
        st.success("✅ Backend Connected")
        if health_data:
            st.write(f"📊 Knowledge Base: {health_data.get('knowledge_base_size', 0)} examples")
    else:
        st.error("❌ Backend Disconnected")
    
    # CVE Intelligence Status
    st.header("🔍 CVE Intelligence")
    cve_data = load_cve_intelligence_data()
    if cve_data:
        st.success(f"✅ CVE Database: {len(cve_data)} entries")
        
        severity_counts = {}
        for cve in cve_data:
            severity = cve['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            st.write(f"🚨 {severity.upper()}: {count}")
    else:
        st.warning("⚠️ CVE data loading...")
    
    # Model Information
    st.header("🤖 Model Information")
    model_info = get_model_info()
    st.write(f"**Model:** {model_info.get('model_name', 'Unknown')}")
    st.write(f"**Training Examples:** {model_info.get('training_examples', 0)}")
    
    # CVE Search Filter
    st.header("🎯 CVE Intelligence Filter")
    severity_filter = st.selectbox(
        "Filter by Severity:",
        ["all", "critical", "high", "medium", "low"]
    )
    
    cve_search = st.text_input("Search CVE:", placeholder="Enter CVE-2025-...")
    
    # Quick Actions
    st.header("⚡ Quick Actions")
    if st.button("🔄 Refresh Status"):
        st.rerun()
    
    if st.button("🧹 Clear Chat"):
        st.session_state.messages = []
        st.rerun()
    
    if st.button("📊 CVE Statistics"):
        if cve_data:
            st.write(f"Total CVEs: {len(cve_data)}")
            avg_cvss = sum(cve['cvss_score'] for cve in cve_data) / len(cve_data)
            st.write(f"Average CVSS: {avg_cvss:.1f}")

# --- Main Content ---
col1, col2 = st.columns([2, 1])

with col1:
    st.header("💬 Professional Security Assistant with CVE Intelligence")
    
    # CVE Intelligence Toggle
    use_cve_intelligence = st.checkbox("🔬 Enable CVE Intelligence Analysis", value=True)
    
    # Display chat messages
    chat_container = st.container()
    with chat_container:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
                if message["role"] == "assistant" and "confidence" in message:
                    confidence = message["confidence"]
                    if confidence > 0.85:
                        st.markdown(f'<span class="severity-low">High Confidence: {confidence:.1%}</span>', unsafe_allow_html=True)
                    elif confidence > 0.7:
                        st.markdown(f'<span class="severity-medium">Medium Confidence: {confidence:.1%}</span>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<span class="severity-high">Lower Confidence: {confidence:.1%}</span>', unsafe_allow_html=True)

    # Chat input
    if prompt := st.chat_input("Ask about cybersecurity, vulnerabilities, or CVE intelligence..."):
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.write(prompt)
        
        # Get AI response
        with st.chat_message("assistant"):
            if use_cve_intelligence and any(keyword in prompt.lower() for keyword in ['cve', 'vulnerability', 'exploit', 'security flaw']):
                with st.spinner("🔬 Analyzing with CVE intelligence..."):
                    # Get vulnerability assessment
                    vuln_assessment = vulnerability_assessment(prompt, severity_filter if severity_filter != "all" else None)
                    
                    if "error" not in vuln_assessment and vuln_assessment.get("total_cves", 0) > 0:
                        st.write("**CVE Intelligence Analysis:**")
                        st.write(f"Found {vuln_assessment['total_cves']} related vulnerabilities")
                        
                        # Display severity distribution
                        col_a, col_b, col_c, col_d = st.columns(4)
                        with col_a:
                            st.metric("Critical", vuln_assessment['severity_distribution']['critical'])
                        with col_b:
                            st.metric("High", vuln_assessment['severity_distribution']['high'])
                        with col_c:
                            st.metric("Medium", vuln_assessment['severity_distribution']['medium'])
                        with col_d:
                            st.metric("Low", vuln_assessment['severity_distribution']['low'])
                        
                        # Show top vulnerabilities
                        if vuln_assessment.get("top_vulnerabilities"):
                            st.write("**Top Related Vulnerabilities:**")
                            for cve in vuln_assessment["top_vulnerabilities"][:5]:
                                st.markdown(f"""
                                <div class="cve-card">
                                    <strong>{cve['cve_id']}</strong> - 
                                    <span class="severity-{cve['severity']}">{cve['severity'].upper()}</span><br>
                                    <small>CVSS: {cve['cvss_score']} | Category: {cve['category']} | Vector: {cve['attack_vector']}</small><br>
                                    <em>{cve['description']}</em>
                                </div>
                                """, unsafe_allow_html=True)
                    
                    # Get regular AI response
                    response, confidence, domain = send_message(prompt)
            else:
                with st.spinner("🤔 Analyzing your security question..."):
                    response, confidence, domain = send_message(prompt)
            
            st.write(response)
            
            # Show confidence indicator
            if confidence > 0.85:
                st.success(f"High Professional Confidence: {confidence:.1%}")
            elif confidence > 0.7:
                st.warning(f"Medium Confidence: {confidence:.1%}")
            else:
                st.info(f"Lower Confidence: {confidence:.1%}")
        
        # Add assistant response to chat history
        st.session_state.messages.append({
            "role": "assistant", 
            "content": response,
            "confidence": confidence
        })

with col2:
    st.header("🎯 CVE Intelligence Examples")
    
    # Professional CVE Questions
    st.subheader("🔍 Vulnerability Assessment")
    cve_questions = [
        "What are the latest critical CVE vulnerabilities?",
        "How do you assess CVE-2025-0168 severity?",
        "What are SQL injection vulnerabilities in 2025?",
        "How do you mitigate web application vulnerabilities?",
        "What are the most dangerous CVEs this year?"
    ]
    
    for i, question in enumerate(cve_questions):
        if st.button(f"🔬 {question}", key=f"cve_{i}"):
            st.session_state.messages.append({"role": "user", "content": question})
            response, confidence, domain = send_message(question)
            st.session_state.messages.append({
                "role": "assistant", 
                "content": response,
                "confidence": confidence
            })
            st.rerun()
    
    # Enterprise Security Questions
    st.subheader("🏢 Enterprise Security")
    enterprise_questions = [
        "How do you conduct enterprise vulnerability management?",
        "What are professional incident response procedures?",
        "How do you implement threat intelligence programs?",
        "What are CVSS scoring best practices?",
        "How do you prioritize vulnerability remediation?"
    ]
    
    for i, question in enumerate(enterprise_questions):
        if st.button(f"🏆 {question}", key=f"enterprise_cve_{i}"):
            st.session_state.messages.append({"role": "user", "content": question})
            response, confidence, domain = send_message(question)
            st.session_state.messages.append({
                "role": "assistant", 
                "content": response,
                "confidence": confidence
            })
            st.rerun()

# --- CVE Intelligence Dashboard ---
st.markdown("---")

# Create tabs for CVE intelligence features
tab1, tab2, tab3, tab4 = st.tabs(["🔍 CVE Database", "📊 Vulnerability Metrics", "🛡️ Risk Assessment", "🚨 Threat Intelligence"])

with tab1:
    st.subheader("🔍 CVE Intelligence Database")
    
    if cve_data:
        # Search and filter functionality
        col1, col2 = st.columns(2)
        
        with col1:
            search_term = st.text_input("Search CVEs:", placeholder="Enter search term...")
        
        with col2:
            category_filter = st.selectbox("Filter by Category:", 
                                         ["all"] + list(set(cve['category'] for cve in cve_data)))
        
        # Filter CVEs
        filtered_cves = cve_data
        
        if search_term:
            filtered_cves = [cve for cve in filtered_cves 
                           if search_term.lower() in cve['description'].lower() or 
                           search_term.upper() in cve['cve_id']]
        
        if category_filter != "all":
            filtered_cves = [cve for cve in filtered_cves if cve['category'] == category_filter]
        
        # Display results
        st.write(f"**Showing {len(filtered_cves)} of {len(cve_data)} CVEs**")
        
        for cve in filtered_cves[:20]:  # Show top 20
            st.markdown(f"""
            <div class="vulnerability-metric">
                <strong>{cve['cve_id']}</strong> - 
                <span class="severity-{cve['severity']}">{cve['severity'].upper()}</span><br>
                <small>CVSS: {cve['cvss_score']} | Category: {cve['category']} | Attack Vector: {cve['attack_vector']}</small><br>
                <em>{cve['description']}</em>
            </div>
            """, unsafe_allow_html=True)

with tab2:
    st.subheader("📊 Vulnerability Metrics & Statistics")
    
    if cve_data:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Severity Distribution:**")
            severity_counts = {}
            for cve in cve_data:
                severity = cve['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                percentage = (count / len(cve_data)) * 100
                st.write(f"{severity.upper()}: {count} ({percentage:.1f}%)")
        
        with col2:
            st.write("**CVSS Score Distribution:**")
            high_cvss = len([cve for cve in cve_data if cve['cvss_score'] >= 7.0])
            medium_cvss = len([cve for cve in cve_data if 4.0 <= cve['cvss_score'] < 7.0])
            low_cvss = len([cve for cve in cve_data if cve['cvss_score'] < 4.0])
            
            st.write(f"High (7.0+): {high_cvss}")
            st.write(f"Medium (4.0-6.9): {medium_cvss}")
            st.write(f"Low (<4.0): {low_cvss}")
        
        # Category distribution
        st.write("**Category Distribution:**")
        category_counts = {}
        for cve in cve_data:
            category = cve['category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            st.write(f"• {category.replace('_', ' ').title()}: {count}")

with tab3:
    st.subheader("🛡️ Enterprise Risk Assessment")
    
    st.write("**Professional Risk Assessment Framework:**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Risk Prioritization:**")
        st.write("• Critical vulnerabilities require immediate action")
        st.write("• High severity vulnerabilities need 72-hour response")
        st.write("• Medium vulnerabilities require weekly assessment")
        st.write("• Low vulnerabilities included in monthly reviews")
    
    with col2:
        st.write("**Enterprise Considerations:**")
        st.write("• Business impact assessment")
        st.write("• Asset criticality evaluation")
        st.write("• Exploit availability analysis")
        st.write("• Compliance requirements review")
    
    if cve_data:
        critical_cves = [cve for cve in cve_data if cve['severity'] == 'critical']
        if critical_cves:
            st.error(f"🚨 **CRITICAL ALERT**: {len(critical_cves)} critical vulnerabilities require immediate attention!")
            st.write("**Top Critical CVEs:**")
            for cve in critical_cves[:5]:
                st.write(f"• {cve['cve_id']} (CVSS: {cve['cvss_score']})")

with tab4:
    st.subheader("🚨 Threat Intelligence Integration")
    
    st.write("**Professional Threat Intelligence Features:**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Intelligence Sources:**")
        st.write("• National Vulnerability Database (NVD)")
        st.write("• MITRE CVE Database")
        st.write("• Professional security research")
        st.write("• Enterprise threat feeds")
    
    with col2:
        st.write("**Analysis Capabilities:**")
        st.write("• Real-time vulnerability correlation")
        st.write("• Threat actor attribution")
        st.write("• Attack pattern analysis")
        st.write("• Professional risk scoring")
    
    # Threat intelligence metrics
    if cve_data:
        st.write("**Current Threat Intelligence Status:**")
        
        col_a, col_b, col_c, col_d = st.columns(4)
        
        with col_a:
            st.metric("Total CVEs", len(cve_data))
        
        with col_b:
            critical_count = len([cve for cve in cve_data if cve['severity'] == 'critical'])
            st.metric("Critical Threats", critical_count)
        
        with col_c:
            avg_cvss = sum(cve['cvss_score'] for cve in cve_data) / len(cve_data)
            st.metric("Avg CVSS Score", f"{avg_cvss:.1f}")
        
        with col_d:
            web_app_count = len([cve for cve in cve_data if 'web' in cve['category']])
            st.metric("Web App CVEs", web_app_count)

# --- Footer ---
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>🛡️ Trendyol-Enhanced Cybersecurity AI v5.0 with CVE Intelligence | 
        🔍 100+ CVE Entries | 
        🏢 Professional Grade | 
        🔒 Enterprise Ready</p>
        <p>Powered by NVD CVE 2025 dataset with advanced threat intelligence capabilities</p>
        <p><strong>Professional vulnerability assessment and enterprise security guidance</strong></p>
    </div>
    """, 
    unsafe_allow_html=True
)
