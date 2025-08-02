"""
Streamlit frontend application for Cyber LLM.
"""

import streamlit as st
import requests
import json
import time
from datetime import datetime
from typing import Dict, Any
import base64

# Configure page
st.set_page_config(
    page_title="Cyber LLM - Ethical Hacking AI Assistant",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API configuration
API_BASE_URL = "http://localhost:8000/api/v1"
HEADERS = {"Content-Type": "application/json"}

def init_session_state():
    """Initialize session state variables."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "access_token" not in st.session_state:
        st.session_state.access_token = None
    if "conversation_history" not in st.session_state:
        st.session_state.conversation_history = []
    if "scan_results" not in st.session_state:
        st.session_state.scan_results = {}

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user with API."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/auth/login",
            json={"username": username, "password": password},
            headers=HEADERS
        )
        
        if response.status_code == 200:
            data = response.json()
            st.session_state.access_token = data["access_token"]
            st.session_state.authenticated = True
            return True
        else:
            st.error("Invalid credentials")
            return False
            
    except requests.RequestException as e:
        st.error(f"Authentication failed: {e}")
        return False

def get_auth_headers() -> Dict[str, str]:
    """Get headers with authentication token."""
    if st.session_state.access_token:
        return {
            **HEADERS,
            "Authorization": f"Bearer {st.session_state.access_token}"
        }
    return HEADERS

def chat_with_ai(message: str, use_rag: bool = True) -> Dict[str, Any]:
    """Send chat message to AI."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/chat/",
            json={
                "message": message,
                "use_rag": use_rag,
                "temperature": 0.7,
                "max_tokens": 2048
            },
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API error: {response.status_code}"}
            
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}"}

def run_nmap_scan(target: str, scan_options: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Nmap scan via API."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/tools/scan/nmap",
            json={
                "tool": "nmap",
                "target": target,
                "options": scan_options
            },
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Scan failed: {response.status_code}"}
            
    except requests.RequestException as e:
        return {"error": f"Scan request failed: {e}"}

def run_nuclei_scan(target: str, templates: list) -> Dict[str, Any]:
    """Execute Nuclei scan via API."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/tools/scan/nuclei",
            json={
                "tool": "nuclei",
                "target": target,
                "options": {"templates": templates}
            },
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Scan failed: {response.status_code}"}
            
    except requests.RequestException as e:
        return {"error": f"Scan request failed: {e}"}

def generate_payload(payload_type: str, language: str = "python") -> Dict[str, Any]:
    """Generate security testing payload."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/tools/payloads/generate",
            params={
                "payload_type": payload_type,
                "target_language": language
            },
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Payload generation failed: {response.status_code}"}
            
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}"}

def login_page():
    """Display login page."""
    st.title("🔒 Cyber LLM - Ethical Hacking AI Assistant")
    st.subheader("Secure Login")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            st.write("### Authentication Required")
            username = st.text_input("Username", value="admin")
            password = st.text_input("Password", type="password", value="admin123")
            
            if st.form_submit_button("Login", use_container_width=True):
                if authenticate_user(username, password):
                    st.success("Login successful!")
                    st.rerun()
                    
        st.info("Demo credentials: admin / admin123")
        
        st.write("### Features")
        st.write("• **AI Chat**: Ethical hacking assistance with RAG")
        st.write("• **Security Tools**: Nmap, Nuclei integration")
        st.write("• **Payload Generation**: Custom security payloads")
        st.write("• **Voice Interaction**: Speech-to-text capabilities")
        st.write("• **Report Generation**: Professional security reports")

def main_interface():
    """Display main application interface."""
    # Sidebar
    with st.sidebar:
        st.title("🔒 Cyber LLM")
        st.write(f"Welcome back!")
        
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.access_token = None
            st.rerun()
        
        st.divider()
        
        # Navigation
        page = st.selectbox(
            "Navigation",
            ["AI Chat", "Security Tools", "Payload Generator", "Voice Assistant", "Reports"]
        )
        
        st.divider()
        
        # Quick stats
        st.write("### Quick Stats")
        st.metric("Chat Messages", len(st.session_state.conversation_history))
        st.metric("Scans Run", len(st.session_state.scan_results))
    
    # Main content area
    if page == "AI Chat":
        ai_chat_page()
    elif page == "Security Tools":
        security_tools_page()
    elif page == "Payload Generator":
        payload_generator_page()
    elif page == "Voice Assistant":
        voice_assistant_page()
    elif page == "Reports":
        reports_page()

def ai_chat_page():
    """AI Chat interface."""
    st.title("🤖 AI Chat Assistant")
    st.write("Ask me anything about ethical hacking, cybersecurity, and penetration testing!")
    
    # Chat configuration
    col1, col2 = st.columns([3, 1])
    
    with col2:
        use_rag = st.checkbox("Use Knowledge Base", value=True, help="Enable RAG for enhanced responses")
        if st.button("Clear History"):
            st.session_state.conversation_history = []
            st.rerun()
    
    # Chat history
    chat_container = st.container()
    
    with chat_container:
        for i, msg in enumerate(st.session_state.conversation_history):
            if msg["role"] == "user":
                st.chat_message("user").write(msg["content"])
            else:
                st.chat_message("assistant").write(msg["content"])
                
                # Show sources if available
                if "sources" in msg and msg["sources"]:
                    with st.expander("📚 Knowledge Sources"):
                        for source in msg["sources"]:
                            st.write(f"• {source}")
    
    # Chat input
    user_input = st.chat_input("Ask about ethical hacking, vulnerabilities, tools...")
    
    if user_input:
        # Add user message
        st.session_state.conversation_history.append({
            "role": "user",
            "content": user_input,
            "timestamp": datetime.now()
        })
        
        # Show user message
        st.chat_message("user").write(user_input)
        
        # Get AI response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                response = chat_with_ai(user_input, use_rag)
            
            if "error" in response:
                st.error(response["error"])
            else:
                st.write(response["response"])
                
                # Show metadata
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.caption(f"Model: {response.get('model_used', 'Unknown')}")
                with col2:
                    st.caption(f"Tokens: {response.get('tokens_used', 0)}")
                with col3:
                    st.caption(f"Time: {response.get('response_time', 0):.2f}s")
                
                # Show sources
                if response.get("sources"):
                    with st.expander("📚 Knowledge Sources"):
                        for source in response["sources"]:
                            st.write(f"• {source}")
                
                # Add to conversation history
                st.session_state.conversation_history.append({
                    "role": "assistant",
                    "content": response["response"],
                    "sources": response.get("sources"),
                    "timestamp": datetime.now()
                })

def security_tools_page():
    """Security tools interface."""
    st.title("🛠️ Security Tools")
    st.write("Integrated security scanning and testing tools")
    
    tab1, tab2 = st.tabs(["Nmap Scanner", "Nuclei Scanner"])
    
    with tab1:
        st.subheader("Nmap Network Scanner")
        
        col1, col2 = st.columns(2)
        
        with col1:
            target = st.text_input("Target", placeholder="example.com or 192.168.1.1")
            scan_type = st.selectbox("Scan Type", ["syn", "tcp", "udp", "ping"])
            timing = st.slider("Timing", 1, 5, 3)
            
        with col2:
            ports = st.text_input("Ports", placeholder="80,443 or 1-1000")
            service_detection = st.checkbox("Service Detection")
            os_detection = st.checkbox("OS Detection")
        
        if st.button("Run Nmap Scan", type="primary"):
            if target:
                scan_options = {
                    "scan_type": scan_type,
                    "timing": timing,
                    "service_detection": service_detection,
                    "os_detection": os_detection
                }
                
                if ports:
                    scan_options["ports"] = ports
                
                with st.spinner("Running Nmap scan..."):
                    result = run_nmap_scan(target, scan_options)
                
                if "error" in result:
                    st.error(result["error"])
                else:
                    st.success(f"Scan completed in {result.get('execution_time', 0):.2f}s")
                    
                    # Store results
                    st.session_state.scan_results[f"nmap_{target}_{datetime.now().strftime('%H%M%S')}"] = result
                    
                    # Display results
                    st.text_area("Scan Output", result["output"], height=400)
            else:
                st.error("Please enter a target")
    
    with tab2:
        st.subheader("Nuclei Vulnerability Scanner")
        
        col1, col2 = st.columns(2)
        
        with col1:
            nuclei_target = st.text_input("Target URL", placeholder="https://example.com")
            
        with col2:
            template_categories = st.multiselect(
                "Template Categories",
                ["technologies/", "vulnerabilities/", "exposures/", "cves/", "misconfiguration/"],
                default=["technologies/", "vulnerabilities/"]
            )
        
        if st.button("Run Nuclei Scan", type="primary"):
            if nuclei_target:
                with st.spinner("Running Nuclei scan..."):
                    result = run_nuclei_scan(nuclei_target, template_categories)
                
                if "error" in result:
                    st.error(result["error"])
                else:
                    st.success(f"Scan completed in {result.get('execution_time', 0):.2f}s")
                    
                    # Store results
                    st.session_state.scan_results[f"nuclei_{nuclei_target}_{datetime.now().strftime('%H%M%S')}"] = result
                    
                    # Display results
                    st.text_area("Scan Output", result["output"], height=400)
            else:
                st.error("Please enter a target URL")

def payload_generator_page():
    """Payload generator interface."""
    st.title("⚔️ Payload Generator")
    st.write("Generate security testing payloads for various vulnerability types")
    
    col1, col2 = st.columns(2)
    
    with col1:
        payload_type = st.selectbox(
            "Payload Type",
            ["xss", "sql_injection", "command_injection", "lfi", "ssrf"]
        )
        
        language = st.selectbox(
            "Output Format",
            ["raw", "python", "bash", "javascript"]
        )
    
    with col2:
        if payload_type == "xss":
            category = st.selectbox("XSS Category", ["basic", "event_handler", "filter_bypass"])
        elif payload_type == "sql_injection":
            category = st.selectbox("SQLi Category", ["basic", "union_based", "boolean_based", "time_based"])
        elif payload_type == "command_injection":
            category = st.selectbox("Command Injection Category", ["basic", "system_info", "encoded"])
        elif payload_type == "lfi":
            category = st.selectbox("LFI Category", ["basic", "null_byte", "php_wrappers"])
        elif payload_type == "ssrf":
            category = st.selectbox("SSRF Category", ["localhost", "bypass", "cloud_metadata"])
        else:
            category = "basic"
    
    if st.button("Generate Payloads", type="primary"):
        with st.spinner("Generating payloads..."):
            result = generate_payload(payload_type, language)
        
        if "error" in result:
            st.error(result["error"])
        else:
            st.success("Payloads generated successfully!")
            
            # Display payload info
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Type**: {result['payload_type']}")
                st.info(f"**Language**: {result['language']}")
            with col2:
                st.info(f"**Generated**: {result['timestamp']}")
            
            # Display description
            if "description" in result:
                st.write("### Description")
                st.write(result["description"])
            
            # Display payload
            st.write("### Generated Payload")
            if language == "raw":
                st.text_area("Payloads", result["payload"], height=300)
            else:
                st.code(result["payload"], language=language if language != "raw" else "text")

def voice_assistant_page():
    """Voice assistant interface."""
    st.title("🎙️ Voice Assistant")
    st.write("Voice-enabled interaction with the Cyber LLM assistant")
    
    st.info("🔊 Voice features are available when the backend voice service is enabled")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Speech Recognition")
        
        uploaded_file = st.file_uploader("Upload Audio File", type=["wav", "mp3", "ogg"])
        
        if uploaded_file is not None:
            st.audio(uploaded_file)
            
            if st.button("Transcribe Audio"):
                st.write("Transcription feature coming soon...")
                # Implementation would integrate with voice API
    
    with col2:
        st.subheader("Text-to-Speech")
        
        tts_text = st.text_area("Text to Speak", placeholder="Enter text for speech synthesis...")
        
        if st.button("Generate Speech"):
            if tts_text:
                st.write("Speech synthesis feature coming soon...")
                # Implementation would integrate with voice API
            else:
                st.error("Please enter text to synthesize")
    
    st.divider()
    
    st.subheader("Voice Commands")
    st.write("Available voice commands:")
    st.write("• *'Hey Cyber, scan [target]'* - Start security scan")
    st.write("• *'Hey Cyber, explain XSS'* - Get vulnerability explanation")
    st.write("• *'Hey Cyber, generate payload'* - Create security payload")
    st.write("• *'Hey Cyber, create report'* - Generate assessment report")

def reports_page():
    """Reports interface."""
    st.title("📊 Security Reports")
    st.write("Generate and manage security assessment reports")
    
    tab1, tab2 = st.tabs(["Generate Report", "View Reports"])
    
    with tab1:
        st.subheader("Generate New Report")
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_title = st.text_input("Report Title", value="Security Assessment Report")
            target_info = st.text_input("Target", placeholder="target.com")
            
        with col2:
            report_format = st.selectbox("Format", ["pdf", "html", "markdown", "json"])
            include_scans = st.multiselect("Include Scan Results", list(st.session_state.scan_results.keys()))
        
        findings = st.text_area("Additional Findings", placeholder="Manual findings and observations...")
        
        if st.button("Generate Report", type="primary"):
            # Mock report generation
            report_data = {
                "title": report_title,
                "target": target_info,
                "scan_results": {k: v for k, v in st.session_state.scan_results.items() if k in include_scans},
                "findings": findings,
                "timestamp": datetime.now().isoformat()
            }
            
            st.success("Report generated successfully!")
            st.json(report_data)
    
    with tab2:
        st.subheader("Scan Results History")
        
        if st.session_state.scan_results:
            for scan_id, result in st.session_state.scan_results.items():
                with st.expander(f"📋 {scan_id}"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Tool**: {result.get('tool', 'Unknown')}")
                    with col2:
                        st.write(f"**Target**: {result.get('target', 'Unknown')}")
                    with col3:
                        st.write(f"**Status**: {result.get('status', 'Unknown')}")
                    
                    if st.button(f"View Details - {scan_id}"):
                        st.json(result)
        else:
            st.info("No scan results available. Run some scans to see results here.")

def main():
    """Main application entry point."""
    init_session_state()
    
    if not st.session_state.authenticated:
        login_page()
    else:
        main_interface()

if __name__ == "__main__":
    main()