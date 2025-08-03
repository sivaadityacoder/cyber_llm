import requests
from openai import OpenAI

def fetch_live_cves(keyword, api_key):
    """
    Fetches live CVE data from the NVD API using a keyword search.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    
    # Only add API key header if provided
    headers = {}
    if api_key and api_key.strip():
        headers["apiKey"] = api_key.strip()

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        found_vulns = []
        for entry in data.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            description = ""
            for desc_entry in cve.get("descriptions", []):
                if desc_entry.get("lang") == "en":
                    description = desc_entry.get("value", "")
                    break
            
            # Extract CVSS score if available
            cvss_score = "N/A"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A")
            
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
        if hasattr(e, 'response') and e.response.status_code == 403:
            print("🔑 This might be an API key issue. Check your NVD API key.")
        elif hasattr(e, 'response') and e.response.status_code == 429:
            print("🚫 Rate limit exceeded. Try again later or use an API key.")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def analyze_with_llm(question, cve_results, api_key):
    """
    Sends the user's question and search results to the LLM for a smart answer.
    """
    if not cve_results:
        return "❌ I couldn't find any specific CVEs for that topic. Please try different keywords like 'SQL injection', 'XSS', 'authentication', or 'buffer overflow'."

    if not api_key or not api_key.strip():
        return "⚠️ OpenAI API key is required for AI analysis. Please enter your API key or enable offline mode."

    try:
        client = OpenAI(api_key=api_key.strip())
        
        prompt_content = "You are a helpful cybersecurity analyst. Based *only* on the following live CVE data, answer the user's question with detailed analysis.\n\n"
        prompt_content += "--- Live CVE Data ---\n"
        for cve in cve_results:
            prompt_content += f"ID: {cve['id']}\n"
            prompt_content += f"Description: {cve['description']}\n"
            prompt_content += f"CVSS Score: {cve.get('cvss_score', 'N/A')}\n"
            prompt_content += f"Published: {cve.get('published', 'Unknown')}\n\n"
        prompt_content += "--- User's Question ---\n"
        prompt_content += question

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity analyst. Provide detailed analysis with risk assessment."},
                {"role": "user", "content": prompt_content}
            ],
            max_tokens=1000,
            temperature=0.7
        )
        return completion.choices[0].message.content
        
    except Exception as e:
        error_msg = str(e)
        if "api_key" in error_msg.lower():
            return "🔑 **API Key Error**: Please check your OpenAI API key. Make sure it's valid and has sufficient credits."
        elif "rate_limit" in error_msg.lower():
            return "🚫 **Rate Limit**: You've exceeded the OpenAI API rate limit. Please try again later."
        elif "insufficient_quota" in error_msg.lower():
            return "💳 **Quota Exceeded**: Your OpenAI API quota has been exceeded. Please check your billing."
        else:
            return f"❌ **LLM Analysis Error**: {error_msg}. Please try again or contact support."