# data_preprocessing.py
# Script to prepare cybersecurity data for fine-tuning the LLM.

import os
import pandas as pd
import json
from sklearn.model_selection import train_test_split

# --- Configuration ---
# Directory containing the raw cybersecurity data.
DATA_DIR = "data"
# Path to save the processed training data.
TRAIN_DATA_PATH = "data/train_dataset.json"
# Path to save the processed testing data.
TEST_DATA_PATH = "data/test_dataset.json"

def process_bug_bounty_reports(file_path):
    """
    Processes bug bounty reports into a Q&A format.
    This is a placeholder; you'll need to adapt it to your specific data format.
    """
    # Example: Assuming reports are in a CSV with 'title' and 'summary' columns.
    df = pd.read_csv(file_path)
    qa_pairs = []
    for _, row in df.iterrows():
        question = f"What is the vulnerability described in the report titled '{row['title']}'?"
        answer = row['summary']
        qa_pairs.append({"instruction": question, "response": answer})
    return qa_pairs

def process_cve_data(file_path):
    """
    Processes CVE data into a Q&A format.
    This is a placeholder; adapt to your CVE data format (e.g., JSON from NVD).
    """
    with open(file_path, 'r') as f:
        cve_data = json.load(f)
    qa_pairs = []
    # This is a simplified example. You would parse the complex CVE JSON structure.
    for item in cve_data.get('CVE_Items', []):
        cve_id = item['cve']['CVE_data_meta']['ID']
        description = item['cve']['description']['description_data'][0]['value']
        question = f"What is CVE-{cve_id}?"
        answer = description
        qa_pairs.append({"instruction": question, "response": answer})
    return qa_pairs

def main():
    """
    Main function to orchestrate data processing.
    """
    all_data = []

    # Process each data source
    # You would add similar logic for OWASP Top 10 and other ethical hacking content.
    # For demonstration, we'll assume the existence of these files.
    if os.path.exists(os.path.join(DATA_DIR, "bug_bounty_reports.csv")):
        all_data.extend(process_bug_bounty_reports(os.path.join(DATA_DIR, "bug_bounty_reports.csv")))
    if os.path.exists(os.path.join(DATA_DIR, "cve_data.json")):
        all_data.extend(process_cve_data(os.path.join(DATA_DIR, "cve_data.json")))

    if not all_data:
        print("No data found to process. Please add data files to the 'data' directory.")
        # Create dummy data if no real data is present for demonstration.
        all_data = [
            {"instruction": "What is SQL Injection?", "response": "SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database."},
            {"instruction": "Explain Cross-Site Scripting (XSS).", "response": "Cross-Site Scripting (XSS) is a type of security vulnerability typically found in web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users."}
        ]

    # Split data into training and testing sets
    train_data, test_data = train_test_split(all_data, test_size=0.1, random_state=42)

    # Save the processed data to JSON files
    with open(TRAIN_DATA_PATH, 'w') as f:
        json.dump(train_data, f, indent=4)
    with open(TEST_DATA_PATH, 'w') as f:
        json.dump(test_data, f, indent=4)

    print(f"Data processing complete. Training data saved to {TRAIN_DATA_PATH}, testing data saved to {TEST_DATA_PATH}")

if __name__ == "__main__":
    main()
