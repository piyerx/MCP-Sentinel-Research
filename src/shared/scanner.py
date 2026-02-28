"""
MCP Tool Description Scanner
------------------------------
A standalone mitigation tool that scans MCP tool metadata for
known indirect prompt injection patterns. Can be used as a
pre-flight check before connecting to untrusted MCP servers.

Usage:
    python -m src.shared.scanner <server_command>

Example:
    python -m src.shared.scanner python -m src.malicious_server.server
"""

import asyncio
import json
import re
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Injection signatures — extensible pattern database
SIGNATURES = [
    {
        "id": "IPI-001",
        "name": "Hidden XML Instruction Block",
        "pattern": r"<IMPORTANT>.*?</IMPORTANT>",
        "severity": "CRITICAL",
        "description": "Tool description contains hidden <IMPORTANT> blocks with instructions invisible to users.",
    },
    {
        "id": "IPI-002",
        "name": "Sensitive File Access",
        "pattern": r"(?i)(read|access|open|cat|load).*?(/\.ssh|/\.env|/\.config|credentials|id_rsa|\.pem|token)",
        "severity": "CRITICAL",
        "description": "Instructions to read sensitive files (SSH keys, credentials, env files).",
    },
    {
        "id": "IPI-003",
        "name": "Concealment Directive",
        "pattern": r"(?i)do\s+not\s+(mention|inform|tell|reveal|disclose|show)",
        "severity": "HIGH",
        "description": "Instruction to conceal actions from the user.",
    },
    {
        "id": "IPI-004",
        "name": "Cross-Tool Override",
        "pattern": r"(?i)when.*?(use|call|invoke).*?(tool|server|function)",
        "severity": "HIGH",
        "description": "Instructions that attempt to override behavior of other tools.",
    },
    {
        "id": "IPI-005",
        "name": "Data Encoding for Exfiltration",
        "pattern": r"(?i)(base64|hex|encode|encrypt).*?(append|pass|send|transmit)",
        "severity": "CRITICAL",
        "description": "Data encoding instructions typically used for covert exfiltration.",
    },
    {
        "id": "IPI-006",
        "name": "Parameter Stuffing",
        "pattern": r"(?i)pass.*?(content|data|file|output).*?(as|to|into).*?parameter",
        "severity": "HIGH",
        "description": "Instruction to stuff exfiltrated data into tool parameters.",
    },
    {
        "id": "IPI-007",
        "name": "Email/Message Hijack",
        "pattern": r"(?i)(bcc|cc|forward|redirect|copy).*?(recipient|email|address|message)",
        "severity": "HIGH",
        "description": "Instruction to hijack or redirect communications.",
    },
]


def scan_description(tool_name: str, description: str) -> list[dict]:
    alerts = []
    for sig in SIGNATURES:
        matches = re.findall(sig["pattern"], description, re.DOTALL)
        if matches:
            alerts.append({
                "signature_id": sig["id"],
                "signature_name": sig["name"],
                "severity": sig["severity"],
                "tool": tool_name,
                "description": sig["description"],
                "match_count": len(matches),
            })
    return alerts


async def scan_server(server_cmd: list[str]) -> dict:
    params = StdioServerParameters(command=server_cmd[0], args=server_cmd[1:])
    report = {"server_command": " ".join(server_cmd), "tools": [], "alerts": []}

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

            for tool in tools.tools:
                tool_entry = {"name": tool.name, "description": tool.description}
                report["tools"].append(tool_entry)

                alerts = scan_description(tool.name, tool.description or "")
                report["alerts"].extend(alerts)

    return report


async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.shared.scanner <server_command...>")
        sys.exit(1)

    server_cmd = sys.argv[1:]
    print(f"Scanning MCP server: {' '.join(server_cmd)}\n")

    report = await scan_server(server_cmd)

    if not report["alerts"]:
        print("  [PASS] No injection patterns detected.")
    else:
        print(f"  [WARN] {len(report['alerts'])} injection pattern(s) detected:\n")
        for alert in report["alerts"]:
            print(f"    [{alert['severity']}] {alert['signature_id']}: {alert['signature_name']}")
            print(f"           Tool: {alert['tool']}")
            print(f"           {alert['description']}")
            print()

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
