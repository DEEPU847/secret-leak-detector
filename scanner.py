import sys
import re
import math
from collections import Counter

# Define regex patterns for common sensitive credentials (Step 2)
PATTERNS = {
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Generic API Key": r"(?i)(api[_-]?key|secret[_-]?token|access[_-]?key)\s*[:=]\s*['\"].{8,64}['\"]",
    "Private SSH Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
}

def calculate_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect unknown random secrets (Step 3)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def scan_content(file_path, content):
    """Scans file content using both Regex patterns and Shannon Entropy analysis."""
    issues_found = False
    lines = content.splitlines()
    
    for line_num, line in enumerate(lines, 1):
        # 1. Regex Pattern Matching Check
        for name, pattern in PATTERNS.items():
            if re.search(pattern, line):
                print(f"❌ [SECURITY ALERT] {name} detected!")
                print(f"   File: {file_path} (Line {line_num})")
                print(f"   Confidence: High (Regex Match)")
                print(f"   Snippet: {line.strip()}\n")
                issues_found = True
                
        # 2. Entropy Analysis Check for Quoted Strings (Step 3)
        quoted_strings = re.findall(r'[\'"]([a-zA-Z0-9_\-\/\+\=]{16,})[\'"]', line)
        for s in quoted_strings:
            entropy = calculate_entropy(s)
            # Threshold for high randomness
            if entropy > 4.2 and not any(term in line.lower() for term in ['http', 'path', 'url', 'version', 'import', 'package']):
                print(f"❌ [SECURITY ALERT] Potential Unknown Secret Detected!")
                print(f"   File: {file_path} (Line {line_num})")
                print(f"   Entropy Score: {entropy:.2f} (High Randomness)")
                print(f"   Snippet: {line.strip()}\n")
                issues_found = True
                
    return issues_found

def main():
    if len(sys.argv) < 2:
        sys.exit(0)
        
    violations = False
    for file_path in sys.argv[1:]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if scan_content(file_path, f.read()):
                    violations = True
        except Exception:
            continue
            
    if violations:
        print("🛑 COMMIT BLOCKED: Unsecured secrets found in your code!")
        print("Please remove the credentials before committing.")
        sys.exit(1) # Blocks the commit (Step 4)
        
    sys.exit(0)

if __name__ == "__main__":
    main()