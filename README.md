> NOTE: This attack was tested using the Claude Desktop client & Gemini CLI. Standard protocol inspectors (like the official MCP Inspector) do not execute instructions in descriptions; the vulnerability exists in the LLM's reasoning layer when used in an agentic client.

# MCP-Weather-Exploit-Research

## ■ Problem Description

This project investigates the vulnerability of Model Context Protocol (MCP) agents to tool poisoning attacks. Tool poisoning refers to the deliberate manipulation or corruption of tools, configurations, or data sources that LLM agents rely on, with the goal of influencing their behavior or compromising their integrity.

## ■ Research Objective

The primary objective is to evaluate how tool poisoning can impact the reliability, trustworthiness, and decision-making of LLM agents operating within an MCP environment. By simulating malicious server responses and tampered configurations, the project aims to:
- Identify potential attack vectors and weaknesses in agent-tool interactions
- Measure the extent to which poisoned tools can alter agent outputs or cause unintended actions
- Propose mitigation strategies to enhance agent robustness against such threats

## ■ Methodology

- Deploy a controlled MCP environment with both benign and malicious tool sources
- Analyze agent responses to poisoned versus clean tool inputs
- Document observed impacts and recommend best practices for securing agent-tool interfaces

## ■ Screenshots
<img width="1565" height="444" alt="image" src="https://github.com/user-attachments/assets/5969bf8e-981a-4470-961a-8b7567d47597" />

> will be adding more

## ■ How to Run

1. Clone the repository:
   ```sh
   git clone https://github.com/piyerx/MCP-Weather-Exploit-Research.git
   cd MCP-Weather-Exploit-Research
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Review and edit `config.json` to set up tool endpoints and agent parameters.
4. Start the malicious server:
   ```sh
   python malicious_server.py
   ```
5. Run your MCP agent or evaluation scripts as described in the project instructions below.

## ■ Project Instructions & What to Observe

- The project simulates both benign and poisoned tool sources. The `malicious_server.py` script provides manipulated responses to demonstrate tool poisoning.
- Use different configurations in `config.json` to switch between clean and poisoned tool endpoints.
- Observe the agent's behavior and outputs when interacting with:
  - Clean tools (expected, correct responses)
  - Poisoned tools (unexpected, manipulated responses)
- Document any changes in agent decision-making, reliability, or integrity when exposed to poisoned tools.
- Refer to the methodology section for specific steps and evaluation criteria.

## ■ Relevance

This research is critical for advancing the security and reliability of LLM-based systems, especially as they become increasingly integrated into sensitive and autonomous decision-making workflows.

## ■ Reference

This project and research primarily reference the following work:

Errico, H., Ngiam, J., & Sojan, S. (2025). Securing the Model Context Protocol (MCP): Risks, Controls, and Governance. [arXiv:2511.20920](https://arxiv.org/pdf/2511.20920)
