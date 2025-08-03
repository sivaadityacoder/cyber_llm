#!/usr/bin/env python3
"""
LLM Training Dataset Preparation
Creates comprehensive dataset for training cybersecurity AI models
"""

import json
import os
from datetime import datetime

def create_training_ready_dataset():
    """Create a comprehensive training dataset ready for LLM fine-tuning"""
    
    print("🤖 Preparing LLM Training Dataset...")
    
    # Load existing training data
    training_data = []
    cve_data = []
    
    try:
        with open('data/enhanced_ethical_hacker_training.json', 'r') as f:
            training_data = json.load(f)
        print(f"✅ Loaded {len(training_data)} training examples")
    except FileNotFoundError:
        print("⚠️ Training data not found")
    
    try:
        with open('data/detailed_cve_database.json', 'r') as f:
            cve_data = json.load(f)
        print(f"✅ Loaded {len(cve_data)} CVE entries")
    except FileNotFoundError:
        print("⚠️ CVE data not found")
    
    # Create LLM-ready training format
    llm_dataset = []
    
    # Convert existing training data to instruction-tuning format
    for example in training_data:
        llm_example = {
            "instruction": example.get("instruction", ""),
            "input": example.get("input", ""),
            "output": example.get("output", ""),
            "category": example.get("category", "cybersecurity"),
            "difficulty": example.get("difficulty", "intermediate"),
            "tags": example.get("tags", [])
        }
        llm_dataset.append(llm_example)
    
    # Convert CVE data to training examples
    for cve in cve_data:
        # Create multiple training examples from each CVE
        
        # Basic CVE query
        basic_cve = {
            "instruction": f"Explain {cve['cve_id']} vulnerability",
            "input": f"What is {cve['cve_id']}?",
            "output": f"{cve['cve_id']}: {cve['title']} - CVSS {cve['cvss_score']}/10.0 ({cve['severity']}). {cve['description']} This {cve['category'].replace('_', ' ')} vulnerability affects {cve['detailed_analysis']['affected_systems']}. {cve['detailed_analysis']['technical_summary']}",
            "category": "CVE Analysis",
            "difficulty": "intermediate",
            "tags": ["cve", cve['category'], "vulnerability_analysis"]
        }
        llm_dataset.append(basic_cve)
        
        # Detailed technical analysis
        technical_cve = {
            "instruction": f"Provide technical analysis of {cve['cve_id']}",
            "input": f"Give me detailed technical information about {cve['cve_id']}",
            "output": f"TECHNICAL ANALYSIS - {cve['cve_id']}: {cve['detailed_analysis']['technical_summary']} ATTACK SCENARIO: {cve['detailed_analysis']['attack_scenario']} EXPLOITATION: Complexity: {cve['detailed_analysis']['exploitation_complexity']}, Privileges: {cve['detailed_analysis']['privileges_required']}, User Interaction: {cve['detailed_analysis']['user_interaction']}",
            "category": "CVE Technical Analysis",
            "difficulty": "advanced",
            "tags": ["cve", "technical_analysis", cve['category']]
        }
        llm_dataset.append(technical_cve)
        
        # Mitigation strategies
        mitigation_cve = {
            "instruction": f"How to mitigate {cve['cve_id']}?",
            "input": f"What are the mitigation strategies for {cve['cve_id']}?",
            "output": f"MITIGATION STRATEGIES for {cve['cve_id']}: " + " ".join([f"{i+1}) {strategy}" for i, strategy in enumerate(cve['detailed_analysis']['mitigation_strategies'])]),
            "category": "CVE Mitigation",
            "difficulty": "intermediate",
            "tags": ["cve", "mitigation", "defense", cve['category']]
        }
        llm_dataset.append(mitigation_cve)
    
    # Add conversational examples
    conversational_examples = [
        {
            "instruction": "Respond as a cybersecurity expert",
            "input": "I need help with security assessment",
            "output": "As a cybersecurity expert, I can assist you with comprehensive security assessments including vulnerability analysis, penetration testing, threat modeling, and security architecture review. I specialize in web application security, network security, cloud security, IoT security, and emerging AI/ML security threats. What specific area would you like to focus on?",
            "category": "Expert Consultation",
            "difficulty": "beginner",
            "tags": ["consultation", "general_security"]
        },
        {
            "instruction": "Explain cybersecurity concepts clearly",
            "input": "What is the difference between vulnerability and exploit?",
            "output": "VULNERABILITY vs EXPLOIT: A vulnerability is a weakness or flaw in a system that could potentially be exploited. An exploit is the actual code, technique, or method used to take advantage of that vulnerability. Think of it like this: a vulnerability is an unlocked door (the weakness), while an exploit is the act of someone walking through that door (taking advantage). Vulnerabilities are discovered through security research, while exploits are developed to weaponize those vulnerabilities.",
            "category": "Security Fundamentals",
            "difficulty": "beginner",
            "tags": ["fundamentals", "definitions"]
        }
    ]
    
    llm_dataset.extend(conversational_examples)
    
    # Create metadata
    dataset_metadata = {
        "dataset_name": "Cybersecurity Expert LLM Training Dataset",
        "version": "1.0",
        "created_date": datetime.now().isoformat(),
        "total_examples": len(llm_dataset),
        "categories": list(set([example["category"] for example in llm_dataset])),
        "description": "Comprehensive cybersecurity training dataset including traditional security, LLM security, CVE analysis, and expert consultation examples",
        "training_format": "instruction_tuning",
        "recommended_epochs": 3,
        "learning_rate": "2e-5",
        "batch_size": 8
    }
    
    # Save training-ready dataset
    os.makedirs('data/llm_training', exist_ok=True)
    
    # Main training file
    training_file = 'data/llm_training/cybersecurity_expert_training.json'
    with open(training_file, 'w') as f:
        json.dump(llm_dataset, f, indent=2)
    
    # Metadata file
    metadata_file = 'data/llm_training/dataset_metadata.json'
    with open(metadata_file, 'w') as f:
        json.dump(dataset_metadata, f, indent=2)
    
    # Create train/validation split (80/20)
    split_idx = int(len(llm_dataset) * 0.8)
    train_data = llm_dataset[:split_idx]
    val_data = llm_dataset[split_idx:]
    
    train_file = 'data/llm_training/train.json'
    val_file = 'data/llm_training/validation.json'
    
    with open(train_file, 'w') as f:
        json.dump(train_data, f, indent=2)
    
    with open(val_file, 'w') as f:
        json.dump(val_data, f, indent=2)
    
    print(f"\n✅ LLM Training Dataset Created!")
    print(f"📁 Main Dataset: {training_file}")
    print(f"📁 Training Split: {train_file} ({len(train_data)} examples)")
    print(f"📁 Validation Split: {val_file} ({len(val_data)} examples)")
    print(f"📁 Metadata: {metadata_file}")
    print(f"📊 Total Examples: {len(llm_dataset)}")
    print(f"🏷️ Categories: {len(dataset_metadata['categories'])}")
    
    return training_file

if __name__ == "__main__":
    create_training_ready_dataset()
