# 🛡️ Secret Leak Detector

A developer-side security utility built for **Problem 3 (Secret Leak Detector)** that prevents developers from accidentally committing sensitive API keys, database passwords, and tokens into Git repositories.

---

## 🚀 Features
- **Git Pre-commit Hook Integration:** Automatically scans staged files before allowing a `git commit` to proceed.
- **Regex Pattern Matching:** Detects high-risk credentials such as AWS access keys, GitHub personal access tokens, and private SSH keys.
- **Shannon Entropy Analysis:** Employs mathematical randomness scoring to catch unknown, randomized secret tokens that standard regular expressions might miss.
- **Instant Terminal Warnings:** Blocks unsafe commits immediately and provides clear file and line number alerts while safeguarding actual secret values.

---

## 🛠️ Tech Stack
- **Language:** Python (`sys`, `re`, `math`, `collections`)
- **Version Control:** Git Hooks (`.git/hooks/pre-commit`)

---

## 📦 Installation & Setup

1. Clone or download this repository into your local machine:
   ```bash
   git clone https://github.com/DEEPU847/secret-leak-detector.git
   cd secret-leak-detector