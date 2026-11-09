# Automated Secret & Credential Leak Detector

A lightweight DevSecOps static analysis utility written in Python to detect hardcoded API keys, tokens, and cryptographic secrets in source code repositories.

## Key Features
- **High-Risk Pattern Detection:** Identifies AWS Access Keys, GitHub PATs, Slack Webhooks, JWT tokens, and private keys.
- **Masked Terminal Output:** Automatically redacts secret content in console outputs to prevent secondary exposure during demonstrations.
- **Smart Directory Traversal:** Automatically bypasses noisy build artifacts and cache folders (`.git`, `node_modules`, `venv`).

## Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/Korrawit450/secret-leak-detector.git](https://github.com/Korrawit450/secret-leak-detector.git)
   cd secret-leak-detector