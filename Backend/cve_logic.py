import requests
from openai import OpenAI

def fetch_live_cves(keyword, api_key):
    """
    Fetches live CVE data from the NVD API using a keyword search.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    headers = {"apiKey": api_key}

    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
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
            found_vulns.append({"id": cve.get("id"), "description": description})
        return found_vulns
        
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to NVD API: {e}")
        return None

def analyze_with_llm(question, cve_results, api_key):
    """
    Sends the user's question and search results to the LLM for a smart answer.
    """
    if not cve_results:
        return "I couldn't find any specific CVEs for that topic. Please try another keyword."

    client = OpenAI(api_key=api_key)
    
    prompt_content = "You are a helpful cybersecurity analyst. Based *only* on the following live CVE data, answer the user's question.\n\n"
    prompt_content += "--- Live CVE Data ---\n"
    for cve in cve_results:
        prompt_content += f"ID: {cve['id']}\nDescription: {cve['description']}\n\n"
    prompt_content += "--- User's Question ---\n"
    prompt_content += question

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity analyst."},
                {"role": "user", "content": prompt_content}
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"An error occurred while connecting to the LLM: {e}"