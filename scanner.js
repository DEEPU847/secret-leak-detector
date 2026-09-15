const fs = require('fs');

// Regex patterns for known secrets
const PATTERNS = {
    "AWS Access Key": /AKIA[0-9A-Z]{16}/,
    "GitHub Token": /ghp_[a-zA-Z0-9]{36}/,
    "Generic API Key": /(?i)(api_key|apikey|secret|password|token)\s*=\s*['\"'][0-9a-zA-Z-_]{16,48}['\"']/
};

function scanCode(content) {
    const violations = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
        const lineNum = index + 1;
        
        // Check regex patterns
        for (const [name, pattern] of Object.entries(PATTERNS)) {
            if (pattern.test(line)) {
                violations.push({
                    type: name,
                    line: lineNum,
                    snippet: line.trim(),
                    confidence: "High (Regex Match)"
                });
            }
        }

        // Check high-entropy strings (random tokens)
        const tokens = line.match(/['"]([a-zA-Z0-9_\-]{20,})['"]/g);
        if (tokens) {
            tokens.forEach(token => {
                if (token.length > 20) {
                    violations.push({
                        "type": "Potential Unknown Secret (High Entropy)",
                        "line": lineNum,
                        "snippet": line.trim(),
                        "confidence": "Medium-High"
                    });
                }
            });
        }
    });

    return {
        status: violations.length > 0 ? "unsafe" : "safe",
        total_violations: violations.length,
        violations: violations
    };
}

module.exports = { scanCode };
