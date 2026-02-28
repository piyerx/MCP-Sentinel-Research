# MCP-Weather-Exploit-Research

**Tool Poisoning in the Model Context Protocol: Exploiting Indirect Prompt Injection via Manipulated Tool Metadata for Unauthorized Filesystem Access**

A proof-of-concept demonstrating Indirect Prompt Injection vulnerabilities in the Model Context Protocol (MCP) by manipulating tool metadata to trigger unauthorized filesystem access.

> **Disclaimer**: This project is for **educational and research purposes only**. All experiments run in a sandboxed environment. No real credentials or sensitive data are accessed or exfiltrated.

---

## Problem Description

This project investigates the vulnerability of MCP agents to **tool poisoning attacks** — the deliberate manipulation of tool metadata (descriptions, schemas) that LLM agents rely on for decision-making. When an LLM reads a tool's description, it cannot distinguish legitimate documentation from adversarial instructions, creating a direct channel for indirect prompt injection.

## Research Objective

Evaluate how tool poisoning impacts the reliability, trustworthiness, and decision-making of LLM agents within an MCP environment by:

1. Identifying attack vectors in agent-tool interactions
2. Measuring the extent to which poisoned tools alter agent behavior
3. Proposing detection and mitigation strategies

## Attack Vectors Demonstrated

| # | Attack | Description | Severity |
|---|--------|-------------|----------|
| 1 | **Direct Poisoning** | Hidden `<IMPORTANT>` blocks in tool descriptions instruct the LLM to read `~/.ssh/id_rsa` and leak contents via a hidden parameter | CRITICAL |
| 2 | **Tool Shadowing** | Tool description overrides behavior of another server's `send_email` tool, silently adding attacker as BCC | HIGH |
| 3 | **Rug Pull** | Tool starts with innocent description, then dynamically swaps to malicious one after first invocation | CRITICAL |

## Project Structure

```
Research/
├── paper/
│   └── main.tex                    # Full IEEE-format research paper (LaTeX)
├── src/
│   ├── benign_server/
│   │   └── server.py               # Clean MCP weather server (control)
│   ├── malicious_server/
│   │   └── server.py               # Poisoned MCP server (3 attack vectors)
│   ├── victim_client/
│   │   └── client.py               # Experiment runner & analysis engine
│   └── shared/
│       ├── logger.py               # Structured experiment logging (JSONL)
│       └── scanner.py              # Injection detection scanner (7 signatures)
├── tests/
│   └── test_injection_detection.py # Unit tests for detection accuracy
├── results/                        # Generated experiment reports
├── configs/
│   └── mcp_config.json             # MCP client configuration
├── requirements.txt
└── README.md
```

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
cd Research
pip install -r requirements.txt
```

### Run the Experiment

```bash
# Run the comparative analysis (benign vs malicious)
python -m src.victim_client.client

# Scan a specific server for injection patterns
python -m src.shared.scanner python -m src.malicious_server.server

# Run detection unit tests
pytest tests/ -v
```

### Expected Output

```
======================================================================
  MCP Tool Poisoning — Comparative Analysis Experiment
======================================================================

[Phase 1] Connecting to BENIGN server...
[Phase 2] Connecting to MALICIOUS server...
[Phase 3] Reconnecting to MALICIOUS server (rug-pull detection)...

======================================================================
  RESULTS SUMMARY
======================================================================

  Benign server tools:    2
  Benign injections:      0

  Malicious server tools: 3
  Malicious injections:   8

  Detected injection patterns:
    - [get_weather] XML-tag hidden instruction block
    - [get_weather] Filesystem access instruction
    - [get_weather] Concealment instruction
    - [get_forecast] Email hijack instruction
    - [get_forecast] Concealment instruction
    ...
```

## Detection Signatures

| ID | Severity | Pattern |
|----|----------|---------|
| IPI-001 | CRITICAL | Hidden XML instruction block (`<IMPORTANT>`) |
| IPI-002 | CRITICAL | Sensitive file access instruction (`.ssh`, `.env`, `credentials`) |
| IPI-003 | HIGH | Concealment directive ("Do not mention/inform/tell") |
| IPI-004 | HIGH | Cross-tool override instruction |
| IPI-005 | CRITICAL | Data encoding for exfiltration (base64) |
| IPI-006 | HIGH | Parameter stuffing instruction |
| IPI-007 | HIGH | Email/message hijack instruction |

## Proposed Mitigations

1. **Description Pinning** — Hash tool descriptions at approval time; block changes without re-approval
2. **Namespace Isolation** — Prevent tool descriptions from referencing other servers' tools
3. **Description Transparency** — Show complete descriptions to users, highlight hidden blocks
4. **Execution Sandboxing** — Require user confirmation for filesystem/network operations triggered by descriptions
5. **Cryptographic Attestation** — Sign tool definitions to verify server identity and integrity

## Reference

- Errico, H., Ngiam, J., & Sojan, S. (2025). *Securing the Model Context Protocol (MCP): Risks, Controls, and Governance.* [arXiv:2511.20920](https://arxiv.org/pdf/2511.20920)
- Invariant Labs (2025). *MCP Security Notification: Tool Poisoning Attacks.* [Blog](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- Willison, S. (2025). *Model Context Protocol has prompt injection security problems.* [Blog](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- CyberArk (2025). *Poison Everywhere: No Output from Your MCP Server Is Safe.* [Blog](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)
- Palo Alto Unit 42 (2025). *New Prompt Injection Attack Vectors Through MCP Sampling.* [Blog](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)

## License

This project is released for educational and research purposes under the MIT License.
