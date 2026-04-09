# Hack Smarter Swarm: AI Pentesting Assistant

**Author:** Tyler Ramsbey  
**Organizations:** [Kairos Sec](https://kairos-sec.com) | [Hack Smarter](https://hacksmarter.org)

## Overview
Hack Smarter Swarm is a multi-agent AI penetration testing assistant built to **assist (not replace)** ethical hackers and security professionals. Powered by [LangGraph](https://python.langchain.com/docs/langgraph/) and Gemini, the swarm acts as your automated reconnaissance and initial vulnerability assessment wingman.

It orchestrates industry-standard open-source tools to autonomously map attack surfaces, verify live web servers, probe for vulnerabilities, and eliminate false positives, saving you time and giving you a head-start on deeper, manual exploitation.

## The Philosophy: Assisting, NEVER Replacing
Unlike many open-source projects that chase full autonomy or try to completely abstract away the human element with a "black box" hack button, this swarm is built purely to be an **assistant**. It handles the tedious, time-consuming tasks: 
- Deduplicating subdomains.
- Correlating `nmap` outputs with live `httpx` findings.
- Running `nuclei` and then actively weeding out false positives for you.

You get a clean, validated `dradis_import.json` and a Markdown report with concrete Proof of Concepts (PoCs). You do the deep-dive manual exploitation.

### How Hack Smarter Swarm is Different
1. **Not Just a Chatbot**: It's an agentic loop driving real CLI tools via subprocesses in your terminal -- not just a web UI where you manually copy and paste scan outputs.
2. **False-Positive Elimination**: Many AI tools blindly trust vulnerability scanners, resulting in bloated, noisy reports. The Swarm explicitly uses `Verification Agents` armed with tools like `curl`, `nc`, and `hydra` to confirm a finding before considering it real.
3. **Local State Management**: Operations run with a persistent `pentest_db.json` ledger, ensuring loops and pivoting strategies are based on unified, deduplicated data.

## Features
- **Multi-Agent Architecture**:
  - **Tactical Recon Specialist**: Handles domain discovery and port scanning.
  - **Vuln Worker**: Identifies web surfaces, runs Nuclei, and verifies vulnerabilities using LLM logic.
  - **Strategy & Reporting Node**: Analyzes results, determines if it should pivot deeper, and generates professional summaries.
- **Deduplication & State Management**: Maintains a persistent local ledger (`pentest_db.json`) of findings across loops.
- **False-Positive Reduction**: Actively verifies potential vulnerabilities using an AI agent armed with `curl`, `nmap`, `nc` (Netcat), `ssh-audit`, `hydra`, and `testssl.sh`. It will then provide the full PoC to make it easy to reproduce. 
- **Reporting Ready**: Automatically outputs:
  - `final_report.md`: A high-level, human-readable executive summary.
  - `dradis_import.json`: A structured JSON file ready for ingestion into reporting platforms like Dradis.

## Prerequisites

### Python Dependencies
Python 3.10+ is recommended. Install the required Python libraries:
```bash
pip install -r requirements.txt
```

### System Dependencies (Pentesting Tools)
The AI interacts with the following command-line binaries. Ensure they are installed and accessible in your system's `$PATH`:
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Nmap](https://nmap.org/)
- [HTTPX Toolkit](https://github.com/projectdiscovery/httpx) (Make sure the alias is `httpx-toolkit`)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- `curl`
- `nc` (Netcat)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [testssl.sh](https://testssl.sh/)

### Environment Variables
You need a Google Gemini API Key. Ensure it is placed in a `.env` file in the root of the project:
```env
GOOGLE_API_KEY="your_api_key_here"
```

## Usage

```bash
python hacksmarter.py -t <target>
```

You can pass a single domain, a comma-separated list of domains, or a `.txt` file containing your scope:
```bash
# Single Target
python hacksmarter.py -t example.com

# Multiple Targets
python hacksmarter.py -t "example.com, 192.168.1.1"

# Target File
python hacksmarter.py -t scope.txt
```

---
