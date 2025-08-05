#!/usr/bin/env python3
"""
Extract all unique prompts from the complete training dataset
"""
import json
import sys
from collections import Counter

def extract_all_prompts():
    """Extract and analyze all prompts from the training dataset"""
    
    print("🔍 Loading Complete NVD CVE Training Dataset...")
    
    try:
        with open('/home/siva/project/cyber_llm/data/complete_nvd_cve_training_dataset.json', 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        return
    
    print(f"📊 Total Training Examples: {len(data):,}")
    
    # Extract unique instructions/prompts
    instructions = []
    inputs = []
    
    for example in data:
        if 'instruction' in example:
            instructions.append(example['instruction'])
        if 'input' in example:
            inputs.append(example['input'])
    
    # Count unique instructions
    unique_instructions = list(set(instructions))
    instruction_counts = Counter(instructions)
    
    print(f"\n📋 PROMPT ANALYSIS:")
    print(f"   Total Instructions: {len(instructions):,}")
    print(f"   Unique Instructions: {len(unique_instructions):,}")
    
    print(f"\n🎯 TOP 20 MOST COMMON PROMPT TYPES:")
    print("=" * 80)
    
    for i, (instruction, count) in enumerate(instruction_counts.most_common(20), 1):
        print(f"{i:2d}. [{count:,}x] {instruction}")
    
    print(f"\n📝 ALL UNIQUE INSTRUCTION PROMPTS:")
    print("=" * 80)
    
    for i, instruction in enumerate(sorted(unique_instructions), 1):
        print(f"{i:3d}. {instruction}")
    
    # Sample inputs analysis
    unique_inputs = list(set(inputs[:1000]))  # Sample first 1000 to avoid memory issues
    print(f"\n💡 SAMPLE INPUT TYPES (First 1000):")
    print("=" * 80)
    
    input_types = set()
    for inp in unique_inputs[:50]:  # Show first 50
        if inp.startswith("CVE ID:"):
            input_types.add("CVE Analysis Request")
        elif "understand" in inp.lower():
            input_types.add("Educational Query")
        elif "CVSS score" in inp:
            input_types.add("CVSS Score Query")
        elif "explain" in inp.lower():
            input_types.add("Explanation Request")
        else:
            input_types.add("General Security Query")
    
    for i, inp_type in enumerate(sorted(input_types), 1):
        print(f"{i}. {inp_type}")
    
    print(f"\n📈 DATASET STATISTICS:")
    print("=" * 50)
    print(f"🔢 Total Training Examples: {len(data):,}")
    print(f"📋 Unique Prompt Templates: {len(unique_instructions):,}")
    print(f"💾 Average Response Length: {sum(len(ex.get('response', '')) for ex in data) // len(data):,} characters")
    
    # Calculate file sizes
    import os
    file_size = os.path.getsize('/home/siva/project/cyber_llm/data/complete_nvd_cve_training_dataset.json')
    print(f"💽 Dataset File Size: {file_size / (1024*1024):.2f} MB")
    
if __name__ == "__main__":
    extract_all_prompts()
