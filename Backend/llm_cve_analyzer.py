import os
import requests
import json
import sys

# --- Configuration ---
# 🔑 IMPORTANT: Paste your NVD API key here.
# It's better to set this as an environment variable in a real project.
NVD_API_KEY = "5c5e59a8-16fb-4e2c-a4fa-4c15d8f9aefc"

# Configure OpenAI client with error handling
try:
    from openai import OpenAI
    # Check if OpenAI API key is available
    openai_api_key = os.getenv('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')
    if openai_api_key:
        client = OpenAI(api_key=openai_api_key)
        USE_OPENAI = True
    else:
        print("⚠️ WARNING: OPENAI_API_KEY not found. Using offline analysis mode.")
        client = None
        USE_OPENAI = False
except ImportError:
    print("⚠️ WARNING: OpenAI library not installed. Using offline analysis mode.")
    client = None
    USE_OPENAI = False

def fetch_live_cves(keyword):
    """
    Fetches live CVE data from the NVD API using a keyword search.
    """
    print(f"\n📡 Connecting to the internet to search for '{keyword}'...")
    
    # The official NVD API endpoint for CVEs
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Parameters for the API call, including the keyword search
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5  # We only need a few results for the LLM
    }
    
    # Headers for the API call, including your API key
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        print(f"🔗 Making request to: {url}")
        print(f"📋 Parameters: {params}")
        
        response = requests.get(url, params=params, headers=headers, timeout=30)
        
        print(f"📊 Response status: {response.status_code}")
        
        # Raise an error if the request was unsuccessful (e.g., 404, 500)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        print(f"✅ Found {len(vulnerabilities)} vulnerabilities")
        
        # Process the results into a simple list
        found_vulns = []
        for entry in vulnerabilities:
            cve = entry.get("cve", {})
            description = ""
            for desc_entry in cve.get("descriptions", []):
                if desc_entry.get("lang") == "en":
                    description = desc_entry.get("value", "")
                    break
            
            # Get CVSS score if available
            cvss_score = "N/A"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
            
            found_vulns.append({
                "id": cve.get("id", "Unknown"), 
                "description": description,
                "cvss_score": cvss_score,
                "published": cve.get("published", "Unknown")
            })
            
        return found_vulns
        
    except requests.exceptions.Timeout:
        print("❌ Error: Request timed out. The NVD API might be slow or unavailable.")
        return None
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to NVD API. Check your internet connection.")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
        if response.status_code == 403:
            print("🔑 This might be an API key issue. Check your NVD API key.")
        elif response.status_code == 429:
            print("🚫 Rate limit exceeded. Try again later.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to NVD API: {e}")
        return None
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON response from NVD API")
        return None

def analyze_with_llm(question, cve_results):
    """
    Sends the user's question and search results to the LLM for a smart answer.
    Falls back to offline analysis if OpenAI is not available.
    """
    if cve_results is None:
        return "Could not connect to the NVD API to fetch live data."
    if not cve_results:
        return f"No live CVEs found for your keyword."

    # Offline analysis if OpenAI is not available
    if not USE_OPENAI:
        return analyze_offline(question, cve_results)

    print("🤖 Connecting to LLM for analysis...")

    # Create the prompt for the LLM
    prompt_content = "You are a helpful cybersecurity analyst. Based *only* on the following live CVE data, answer the user's question.\n\n"
    prompt_content += "--- Live CVE Data ---\n"
    for cve in cve_results:
        prompt_content += f"ID: {cve['id']}\n"
        prompt_content += f"Description: {cve['description']}\n"
        prompt_content += f"CVSS Score: {cve['cvss_score']}\n"
        prompt_content += f"Published: {cve['published']}\n\n"
    prompt_content += "--- User's Question ---\n"
    prompt_content += question

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity analyst."},
                {"role": "user", "content": prompt_content}
            ],
            max_tokens=1000,
            temperature=0.3
        )
        return completion.choices[0].message.content
    except Exception as e:
        print(f"❌ Error with OpenAI API: {e}")
        print("🔄 Falling back to offline analysis...")
        return analyze_offline(question, cve_results)

def analyze_offline(question, cve_results):
    """
    Provides offline analysis when OpenAI is not available.
    """
    print("🔧 Using offline analysis mode...")
    
    analysis = f"📊 **CVE Analysis Results** (Offline Mode)\n\n"
    analysis += f"🔍 **Query**: {question}\n"
    analysis += f"📈 **Found {len(cve_results)} vulnerabilities**\n\n"
    
    for i, cve in enumerate(cve_results, 1):
        analysis += f"**{i}. {cve['id']}**\n"
        analysis += f"   📋 Description: {cve['description'][:200]}...\n"
        analysis += f"   🎯 CVSS Score: {cve['cvss_score']}\n"
        analysis += f"   📅 Published: {cve['published']}\n\n"
    
    # Basic risk assessment
    high_risk_count = sum(1 for cve in cve_results if isinstance(cve['cvss_score'], (int, float)) and cve['cvss_score'] >= 7.0)
    analysis += f"⚠️ **Risk Assessment**: {high_risk_count}/{len(cve_results)} high-risk vulnerabilities (CVSS ≥ 7.0)\n"
    
    return analysis

# --- Main Program ---
if __name__ == "__main__":
    print("🔒 **Enhanced CVE Analyzer with Error Handling**")
    print("=" * 50)
    
    # Validate NVD API key
    if not NVD_API_KEY or NVD_API_KEY == "your-api-key-here":
        print("⚠️ WARNING: No valid NVD API key found. You may hit rate limits.")
        print("💡 Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key")
    
    try:
        search_keyword = input("Enter a keyword to search for online (e.g., 'Microsoft Exchange'): ").strip()
        if not search_keyword:
            print("❌ Error: Empty search keyword. Please provide a valid keyword.")
            sys.exit(1)
            
        user_question = input("What do you want to know about these vulnerabilities? (e.g., 'summarize the main risks'): ").strip()
        if not user_question:
            user_question = "Provide a summary of these vulnerabilities and their risks."

        # 1. Fetch live data from the internet
        print(f"\n🔍 Searching for CVEs related to: '{search_keyword}'")
        cve_results = fetch_live_cves(search_keyword)

        # 2. Send to LLM for analysis (or use offline analysis)
        llm_answer = analyze_with_llm(user_question, cve_results)

        # Print the final, LLM-generated answer
        print("\n" + "=" * 50)
        print("🤖 **AI Analysis (from Live Data)**")
        print("=" * 50)
        print(llm_answer)
        
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("💡 Please check your internet connection and try again.")
        sys.exit(1)