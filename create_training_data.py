import json
import pandas as pd
import os

# Create comprehensive ethical hacking training data
def create_ethical_hacking_dataset():
    training_data = []
    
    # Web Application Security
    training_data.extend([
        {
            "instruction": "What is SQL injection and how can it be prevented?",
            "response": "SQL injection is a code injection technique that exploits vulnerabilities in an application's software when user input is not properly sanitized before being included in SQL queries. Prevention methods include: 1) Using parameterized queries/prepared statements, 2) Input validation and sanitization, 3) Escaping all user input, 4) Using stored procedures, 5) Implementing least privilege principles for database connections, 6) Regular security testing and code reviews."
        },
        {
            "instruction": "Explain Cross-Site Scripting (XSS) and its types.",
            "response": "Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. Types include: 1) Stored XSS: malicious script stored on target server, 2) Reflected XSS: script reflected off web server, 3) DOM-based XSS: payload executed in victim's browser by modifying DOM. Prevention: validate/sanitize input, encode output, use Content Security Policy (CSP), implement proper session management."
        },
        {
            "instruction": "What is Cross-Site Request Forgery (CSRF) and how to prevent it?",
            "response": "CSRF is an attack that forces users to execute unwanted actions on web applications where they're authenticated. Prevention methods: 1) Use CSRF tokens (synchronizer tokens), 2) Verify HTTP Referer header, 3) Implement SameSite cookie attribute, 4) Use custom headers for AJAX requests, 5) Re-authenticate for sensitive operations, 6) Implement proper CORS policies."
        },
        {
            "instruction": "How do you perform ethical reconnaissance on a target?",
            "response": "Ethical reconnaissance involves gathering information legally: 1) Passive reconnaissance: DNS enumeration, WHOIS lookups, social media research, search engine queries, 2) Active reconnaissance: port scanning, service enumeration, network mapping (with permission), 3) OSINT tools: theHarvester, Maltego, Shodan, 4) Always ensure proper authorization and scope definition, 5) Document findings professionally, 6) Respect privacy and legal boundaries."
        }
    ])
    
    # Network Security
    training_data.extend([
        {
            "instruction": "What is a man-in-the-middle attack and how can it be prevented?",
            "response": "A man-in-the-middle (MITM) attack occurs when an attacker intercepts communication between two parties. Prevention: 1) Use strong encryption (TLS/SSL), 2) Implement certificate pinning, 3) Use VPNs for sensitive communications, 4) Verify SSL certificates, 5) Avoid public Wi-Fi for sensitive operations, 6) Use mutual authentication, 7) Implement HSTS (HTTP Strict Transport Security)."
        },
        {
            "instruction": "Explain port scanning and its ethical considerations.",
            "response": "Port scanning identifies open ports and services on a target system. Ethical considerations: 1) Only scan systems you own or have explicit permission to test, 2) Use tools like Nmap responsibly, 3) Common techniques: TCP connect scan, SYN scan, UDP scan, 4) Stealth scanning to avoid detection, 5) Always document scope and get written authorization, 6) Be aware of legal implications, 7) Avoid disrupting services unnecessarily."
        }
    ])
    
    # System Security
    training_data.extend([
        {
            "instruction": "What are privilege escalation attacks and how to prevent them?",
            "response": "Privilege escalation involves gaining higher-level permissions than initially granted. Types: 1) Horizontal: access to another user's account, 2) Vertical: gaining administrative privileges. Prevention: 1) Implement least privilege principle, 2) Regular security updates and patches, 3) Proper access controls and monitoring, 4) Use application whitelisting, 5) Implement UAC/sudo properly, 6) Regular security audits, 7) Monitor system logs for suspicious activities."
        },
        {
            "instruction": "How do buffer overflow attacks work and how to prevent them?",
            "response": "Buffer overflow occurs when data written to a buffer exceeds its capacity, potentially overwriting adjacent memory. Prevention: 1) Use safe programming languages (Python, Java), 2) Implement bounds checking, 3) Use stack canaries, 4) Enable DEP (Data Execution Prevention), 5) Use ASLR (Address Space Layout Randomization), 6) Code reviews and static analysis, 7) Use safe functions (strncpy instead of strcpy)."
        }
    ])
    
    # Cryptography and Data Protection
    training_data.extend([
        {
            "instruction": "What are the best practices for password security in ethical hacking?",
            "response": "Password security best practices: 1) Use strong, unique passwords (12+ characters), 2) Implement multi-factor authentication, 3) Use password managers, 4) Regular password rotation for sensitive accounts, 5) Avoid password reuse, 6) Use passphrases when possible, 7) Implement account lockout policies, 8) Hash passwords with salt (bcrypt, Argon2), 9) Monitor for breached credentials."
        },
        {
            "instruction": "Explain symmetric vs asymmetric encryption in cybersecurity.",
            "response": "Symmetric encryption uses the same key for encryption and decryption (AES, DES). Advantages: fast, efficient for large data. Disadvantages: key distribution problem. Asymmetric encryption uses public/private key pairs (RSA, ECC). Advantages: secure key exchange, digital signatures. Disadvantages: slower, more computationally intensive. Best practice: use hybrid approach - asymmetric for key exchange, symmetric for data encryption."
        }
    ])
    
    # Incident Response and Forensics
    training_data.extend([
        {
            "instruction": "What are the steps in an ethical hacking incident response?",
            "response": "Incident response steps: 1) Preparation: establish incident response team and procedures, 2) Detection and Analysis: identify and analyze the incident, 3) Containment: isolate affected systems to prevent spread, 4) Eradication: remove threats and vulnerabilities, 5) Recovery: restore systems and monitor for issues, 6) Lessons Learned: document findings and improve processes. Always maintain evidence integrity and follow legal requirements."
        },
        {
            "instruction": "How do you conduct ethical digital forensics?",
            "response": "Ethical digital forensics process: 1) Legal authorization and proper documentation, 2) Create forensic images (bit-by-bit copies), 3) Maintain chain of custody, 4) Use write-blocking devices, 5) Document all procedures and findings, 6) Use validated forensic tools, 7) Preserve evidence integrity, 8) Follow industry standards (NIST, ISO), 9) Respect privacy and legal boundaries, 10) Provide clear, factual reports."
        }
    ])
    
    # Social Engineering and Human Factors
    training_data.extend([
        {
            "instruction": "What is social engineering and how can organizations defend against it?",
            "response": "Social engineering manipulates people to divulge confidential information or perform actions that compromise security. Defense strategies: 1) Security awareness training, 2) Establish verification procedures, 3) Create security policies and procedures, 4) Implement multi-person authorization for sensitive operations, 5) Regular phishing simulations, 6) Foster security-conscious culture, 7) Use technical controls (email filtering, caller ID), 8) Incident reporting procedures."
        }
    ])
    
    # Legal and Ethical Considerations
    training_data.extend([
        {
            "instruction": "What are the legal and ethical boundaries in ethical hacking?",
            "response": "Legal and ethical boundaries: 1) Always obtain written authorization before testing, 2) Stay within defined scope and timeframes, 3) Respect data privacy and confidentiality, 4) Follow responsible disclosure practices, 5) Comply with local and international laws, 6) Avoid causing damage or disruption, 7) Document all activities properly, 8) Consider third-party impacts, 9) Maintain professional integrity, 10) Report findings responsibly to appropriate parties."
        },
        {
            "instruction": "What is responsible disclosure in cybersecurity?",
            "response": "Responsible disclosure is the practice of reporting security vulnerabilities to vendors or organizations in a coordinated manner. Process: 1) Discover vulnerability through authorized testing, 2) Document the issue thoroughly, 3) Contact the vendor/organization privately, 4) Provide reasonable time for fixes (30-90 days), 5) Work collaboratively on remediation, 6) Coordinate public disclosure timing, 7) Credit researchers appropriately, 8) Follow established disclosure policies, 9) Consider public safety and user protection."
        }
    ])
    
    # Tool Usage and Methodology
    training_data.extend([
        {
            "instruction": "What are essential tools for ethical hacking and their proper usage?",
            "response": "Essential ethical hacking tools: 1) Network scanning: Nmap, Masscan, 2) Vulnerability assessment: Nessus, OpenVAS, 3) Web application testing: Burp Suite, OWASP ZAP, 4) Penetration testing: Metasploit, Cobalt Strike, 5) Wireless testing: Aircrack-ng, Kismet, 6) Social engineering: SET, Gophish, 7) Forensics: Autopsy, Volatility, 8) Always use tools ethically, with proper authorization, and within legal boundaries. Keep tools updated and understand their impact."
        }
    ])
    
    return training_data

# Create and save the dataset
if __name__ == "__main__":
    # Create data directory if it doesn't exist
    os.makedirs("data", exist_ok=True)
    
    # Generate training data
    dataset = create_ethical_hacking_dataset()
    
    # Save as JSON for training
    with open("data/train_dataset.json", "w") as f:
        json.dump(dataset, f, indent=2)
    
    # Create a smaller test dataset (using last 20% of data)
    test_size = int(len(dataset) * 0.2)
    test_dataset = dataset[-test_size:]
    
    with open("data/test_dataset.json", "w") as f:
        json.dump(test_dataset, f, indent=2)
    
    print(f"Created training dataset with {len(dataset)} examples")
    print(f"Created test dataset with {len(test_dataset)} examples")
    print("Files saved: data/train_dataset.json, data/test_dataset.json")
