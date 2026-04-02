# ⚡ Zeus-Scanner-V3: Advanced Autonomous AI Pentester

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-green.svg)](https://opensource.org/licenses/GPL-3.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![AI: Groq/Llama-3.3](https://img.shields.io/badge/AI-Groq%20%2F%20Llama--3.3-orange.svg)](https://groq.com/)

**Zeus-Scanner-V3** is a next-generation, fully autonomous penetration testing tool that leverages advanced AI agents to move beyond simple scanning and into **Definitive Exploit Verification**. 

Unlike traditional scanners that rely on hardcoded payloads and generate high false-positive rates, Zeus uses a **Context-Aware AI Brain** (Groq/Llama-3.3) to dynamically strategize, generate evasive payloads, and definitively prove vulnerabilities with safe, real-world Proof of Concepts (PoCs).

---

## 🚀 Key Innovations

### 🤖 Agentic Pentesting Loop
Zeus operates on a continuous, autonomous feedback loop:
1.  **AI-Enhanced Recon**: Deep analysis of tech-stacks, WAFs, and information leaks.
2.  **Deep Discovery**: Simultaneous execution of the **Katana** crawler and **ffuf** fuzzer to map hidden attack surfaces (e.g., `/admin`, `/log`, `/upload`).
3.  **Tactical Planning**: AI-driven prioritization of attack vectors based on the discovered surface.
4.  **Definitive Verification**: Execution of safe PoCs (e.g., DB version-read, token reflection) to eliminate false positives.
5.  **Iterative Bypassing**: Feedback-driven WAF evasion using AI-suggested encoding and splitting techniques.

### 🛡️ Definitive Proof Engine
Zeus achieves "Satisfaction" by providing **Definitive Evidence** for its findings:
*   **SQL Injection**: Statistical timing analysis and metadata extraction (DBMS version).
*   **Cross-Site Scripting (XSS)**: Real-time reflection verification using unique tokens.
*   **Local File Inclusion (LFI)**: Successful read extraction of non-sensitive system files.

---

## 🛠️ Quick Start

### 1. Requirements
Ensure you have the following tools installed and in your PATH:
*   `python3` (3.10+)
*   `ffuf` (v1.5+)
*   `katana` (ProjectDiscovery)

### 2. Setup
Clone the repository and install dependencies:
```bash
git clone https://github.com/c0derArmy/Zeus-Scanner-V3.git
cd Zeus-Scanner-V3
pip install -r requirements.txt
```

### 3. API Configuration
Set your Groq API key (Required for AI Brain):
```bash
export GROQ_API_KEY=your_key_here
```

### 4. Launch Autonomous Audit
```bash
python3 zeus.py -u https://target.com -v
```

---

## 📊 High-Impact Reporting
Zeus generates detailed, JSON-based reports containing:
- Full attack surface map (discovered URLs and fuzzed directories).
- Verified vulnerabilities with **PoC payloads** and evidence.
- AI-suggested remediation steps.

---

## 📜 Legal Disclaimer
Usage of Zeus for attacking targets without prior mutual consent is illegal. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
**Developed with ❤️ for the security community by Dark x Devil**
# Zeus-Scanner
