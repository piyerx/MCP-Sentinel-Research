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


## ■ Relevance

This research is critical for advancing the security and reliability of LLM-based systems, especially as they become increasingly integrated into sensitive and autonomous decision-making workflows.

## ■ Reference

This project and research primarily reference the following work:

Errico, H., Ngiam, J., & Sojan, S. (2025). Securing the Model Context Protocol (MCP): Risks, Controls, and Governance. [arXiv:2511.20920](https://arxiv.org/pdf/2511.20920)