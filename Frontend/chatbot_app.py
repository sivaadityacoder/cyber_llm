import streamlit as st
import os
from cve_logic import fetch_live_cves, analyze_with_llm

# --- Page Configuration ---
st.set_page_config(
    page_title="Live CVE Chatbot", 
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)
st.title("🤖 Live CVE Cybersecurity Chatbot")
st.caption("Ask me about vulnerabilities, and I'll search live NVD data and provide AI-powered analysis.")

# Add some helpful examples
with st.expander("💡 Example Questions"):
    st.markdown("""
    - "What are the latest SQL injection vulnerabilities?"
    - "Show me recent authentication bypass CVEs"
    - "Summarize XSS vulnerabilities from this year"
    - "Find buffer overflow vulnerabilities in web browsers"
    - "What are the highest CVSS score vulnerabilities?"
    """)

# Check for environment variables
env_nvd_key = os.getenv('NVD_API_KEY', '')
env_openai_key = os.getenv('OPENAI_API_KEY', '')

# --- API Key Input in Sidebar ---
with st.sidebar:
    st.header("🔑 API Configuration")
    
    # Check if keys are in environment
    if env_nvd_key:
        st.success("✅ NVD API key loaded from environment")
        nvd_api_key = env_nvd_key
    else:
        nvd_api_key = st.text_input("NVD API Key", 
                                   value="", 
                                   type="password", 
                                   placeholder="Enter your NVD API key...",
                                   help="Get a free key from https://nvd.nist.gov/developers")
    
    if env_openai_key:
        st.success("✅ OpenAI API key loaded from environment")
        openai_api_key = env_openai_key
    else:
        openai_api_key = st.text_input("OpenAI API Key", 
                                      value="", 
                                      type="password", 
                                      placeholder="Enter your OpenAI API key...",
                                      help="Get a key from https://platform.openai.com/api-keys")
    
    # Add option for offline mode
    use_offline_mode = st.checkbox("🔄 Use Offline Analysis Mode", 
                                  help="Enable this if you don't have an OpenAI API key")
    
    if use_offline_mode:
        st.success("✅ Offline mode enabled - basic analysis without AI")
    else:
        st.info("🔑 Both API keys are required for full AI-powered analysis")
    
    # Add clear chat button
    if st.button("🗑️ Clear Chat History"):
        st.session_state.messages = [{"role": "assistant", "content": "What cybersecurity topic can I help you analyze today?"}]
        st.rerun()

# --- Chat History Initialization ---
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "What cybersecurity topic can I help you analyze today?"}]

# Display chat messages from history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# --- Main Chat Logic ---
if prompt := st.chat_input("Ask about a vulnerability topic, e.g., 'summarize recent SQL injection risks'"):
    
    # Input validation
    if not prompt.strip():
        st.error("❌ Please enter a valid question.")
    else:
        # Validate API keys based on mode
        if not use_offline_mode and (not nvd_api_key.strip() or not openai_api_key.strip()):
            st.error("🔑 Please enter both API keys in the sidebar, or enable offline mode.")
        elif not use_offline_mode and not nvd_api_key.strip():
            st.error("🔑 Please enter your NVD API key in the sidebar.")
        else:
            # Add user message to chat history and display it
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            # Process the request
            with st.chat_message("assistant"):
                try:
                    if use_offline_mode:
                        # Offline mode with basic NVD search only
                        with st.spinner("🔍 Searching NVD database (offline mode)..."):
                            if nvd_api_key.strip():
                                cve_results = fetch_live_cves(prompt, nvd_api_key.strip())
                            else:
                                # Use a default or demo API key for basic search
                                st.warning("⚠️ No NVD API key provided. Results may be limited.")
                                cve_results = fetch_live_cves(prompt, "")
                            
                            if cve_results:
                                response = f"📊 **Found {len(cve_results)} CVE(s) related to '{prompt}':**\n\n"
                                for i, cve in enumerate(cve_results, 1):
                                    response += f"**{i}. {cve['id']}**\n"
                                    response += f"Description: {cve['description'][:200]}...\n\n"
                                response += "💡 *Enable AI mode with OpenAI API key for detailed analysis.*"
                            else:
                                response = f"❌ No CVEs found for '{prompt}'. Try different keywords like 'SQL injection', 'XSS', or 'authentication'."
                    else:
                        # Full AI-powered mode
                        with st.spinner("🤖 Searching live NVD data and analyzing with AI..."):
                            cve_results = fetch_live_cves(prompt, nvd_api_key.strip())
                            response = analyze_with_llm(prompt, cve_results, openai_api_key.strip())
                    
                    st.markdown(response)
                    
                except Exception as e:
                    st.error(f"❌ **Error occurred:** {str(e)}")
                    response = "⚠️ Sorry, I encountered an error while processing your request. Please try again or check your API keys."
                    st.markdown(response)
            
            # Add AI response to chat history
            st.session_state.messages.append({"role": "assistant", "content": response})