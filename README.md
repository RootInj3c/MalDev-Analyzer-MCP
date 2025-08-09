# MalDev Analyzer MCP

**Built for red teamers, by red teamers** - an MCP-powered assistant for malware development, OPSEC testing, and custom loader design during red team engagements.

MalDev Analyzer MCP is designed to help offensive security professionals and malware developers quickly evaluate Windows binaries for traits that may impact stealth, functionality, or OPSEC. Whether you're building a loader, refining an implant, or validating payload security posture, this tool provides fast, targeted insights.

# Why?

As a red-teamer - in real-world red team engagements, time is a luxury.
Most malware analysis and OPSEC checks require juggling a patchwork of GUI tools, including PE-Bear, Detect-It-Easy, Resource Hacker, and YARA scanners, among others. Each one demands manual clicks, context switching, and repetitive tasks just to extract the handful of indicators you care about.

**MalDev Analyzer MCP** was built to eliminate that friction.
By embedding a full suite of PE inspection, loader analysis, and OPSEC checks directly into your MCP-compatible IDE (like Cursor or Claude's MCP mode), you can query and analyze binaries without leaving your workflow.

Instead of:
- Opening a GUI
- Navigating menus
- Exporting intermediate results
- Manually correlating strings, IAT entries, entropy values, and section flags

Now you can now simply ask your MCP assistant to "Check this loader for suspicious API calls and section anomalies" and get a structured, actionable output instantly.

This means faster turnarounds, less human error, and more focus on **developing and refining your custom loaders** - not wrestling with a dozen different GUIs.

---

## ✨ Key Features

- **MCP Integration** – Works with the [Model Context Protocol](https://modelcontextprotocol.io/) to interact directly with compatible AI assistants like Cursor.
- **Binary Trait Analysis** – Identify patterns common in real-world malware and red team tooling.
- **OPSEC Checks** – Spot traits that could raise detection risk during engagements.
- **Custom Loader Support** – Designed with loader development workflows in mind.

---

## 🛠 Included Analysis Tools

| Tool | Purpose |
|------|---------|
| **File Hashing** | Compute SHA-256 and MD5 hashes for quick identification. |
| **String Extraction** | Extract top ASCII/UTF-16 strings to quickly surface suspicious terms. |
| **Suspicious API Detection** | Flag WinAPI calls often used in malware development. |
| **C2 Framework Indicators** | Detect known C2 framework names embedded in binaries. |
| **Section Analysis** | Identify unusual or risky PE section names. |
| **Shannon Entropy** | Detect high-entropy data that may indicate encryption/packing. |
| **Import Table (IAT) Analysis** | Compare declared imports to discovered API usage to spot hiding/obfuscation. |
| **Export Table Analysis** | Highlight exports with suspicious keywords or patterns. |
| **PE Metadata Information** | Extract basic file metadata for further profiling. |
| **PE Sections Inspection** | Perform heuristic shellcode detection for raw blobs or embedded PE sections.  |
---

## 📋 Prerequisites

- Python 3.8 or higher with installed dependencies
- MCP Client (Tested with Cursor IDE)

## 🚀 Quick Installtion

### 1. Install dependencies:
```bash
git clone https://github.com/RootInj3c/MalDev-Analyzer-MCP.git
cd MalDev-Analyzer-MCP
```

### 2. Install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Configure in MCP Client
Add to your MCP servers JSON (or equivalent MCP client config):
```json
{
  "mcpServers": {
    "maldev-analyzer": {
      "command": "python",
      "args": ["PATH/TO/maldev_analyzer.py"]
    }
  }
}
```

## 🔧 Example MCP Queries
**Example queries you can ask through the MCP:**
- "Scan this file for suspicious API calls and potential IAT hiding"
- "Check this binary for section anomalies or known packer signatures"
- "Analyze this loader for C2 indicators and hardcoded framework names"
- "Extract the top suspicious strings from this executable"
- "Perform export table analysis on this file"
- "Check file hashes and entropy score"
- "Identify any suspicious persistence or injection-related APIs"
- "Run full OPSEC analysis on this loader for red team use"

## 📜 License

This project is licensed under the MIT License - see the *LICENSE* file for details.

## ⚠ Disclaimer

This tool is intended only for authorized security testing, research, and educational purposes in controlled environments. Misuse of this tool for malicious purposes is prohibited and may be illegal. The authors assume no liability for misuse.
