import json
import os

# --- Configuration ---
# Make sure your CVE data file is in a 'data' folder next to this script.
CVE_DATA_FILE = os.path.join("data", "nvdcve-2.0-2025.json")

def load_vulnerabilities(filepath):
    """
    Loads the vulnerability data from the JSON file.
    """
    print(f"Loading data from {filepath}...")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load()
        # The vulnerabilities are stored under the 'vulnerabilities' key.
        return data.get("vulnerabilities", [])
    except FileNotFoundError:
        print(f"❌ ERROR: The file was not found at '{filepath}'. Please check the path.")
        return None
    except json.JSONDecodeError:
        print(f"❌ ERROR: The file '{filepath}' is not a valid JSON file.")
        return None

def search_vulnerabilities(vulnerabilities, keyword):
    """
    Searches for a keyword in the descriptions of the vulnerabilities.
    """
    found_vulns = []
    search_keyword = keyword.lower()

    if not vulnerabilities:
        return found_vulns

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        
        # Get the English description
        description = ""
        for desc_entry in cve.get("descriptions", []):
            if desc_entry.get("lang") == "en":
                description = desc_entry.get("value", "")
                break
        
        # Check if the keyword is in the description
        if search_keyword in description.lower():
            cve_id = cve.get("id", "N/A")
            # Create a simple result dictionary
            result = {
                "id": cve_id,
                "description": description
            }
            found_vulns.append(result)
            
    return found_vulns

def main():
    """
    The main function to run the search tool.
    """
    print("--- Simple CVE Search Tool ---")
    
    # Load the data once at the start
    vulnerabilities = load_vulnerabilities(CVE_DATA_FILE)
    
    if vulnerabilities is None:
        print("Could not load vulnerability data. Exiting.")
        return # Exit the program if data loading fails

    print(f"✅ Successfully loaded {len(vulnerabilities)} CVE entries.")

    # Loop forever to allow multiple searches
    while True:
        # Get input from the user
        print("\nType a keyword to search for (or 'quit' to exit):")
        keyword = input("> ")

        if keyword.lower() == 'quit':
            print("Goodbye! 👋")
            break # Exit the loop and end the program

        print(f"\nSearching for '{keyword}'...")
        results = search_vulnerabilities(vulnerabilities, keyword)

        # --- Display the results ---
        if not results:
            print("No vulnerabilities found with that keyword.")
        else:
            print(f"Found {len(results)} matching vulnerabilities:")
            # Print the details for each found vulnerability
            for vuln in results[:10]: # Limit to showing the first 10 results
                print("-" * 20)
                print(f"CVE ID: {vuln['id']}")
                print(f"Description: {vuln['description'][:200]}...") # Show first 200 chars
    
# --- Run the main function when the script is executed ---
if __name__ == "__main__":
    main()