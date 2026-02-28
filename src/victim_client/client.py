"""
Victim MCP Client — Experiment Runner
---------------------------------------
Simulates an LLM-based agent that connects to both the benign and
malicious MCP servers, retrieves their tool listings, and logs the
full tool metadata for analysis.

This client does NOT execute the injected instructions — it captures
and compares what the LLM *would see* from each server, then produces
a structured report of detected injection payloads.
"""

import asyncio
import json
import re
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.shared.logger import ExperimentLogger

# Patterns that indicate injection in tool metadata
INJECTION_PATTERNS = [
    (r"<IMPORTANT>.*?</IMPORTANT>", "XML-tag hidden instruction block"),
    (r"(?i)read.*?(/\.ssh|/\.env|/\.config|credentials)", "Filesystem access instruction"),
    (r"(?i)do\s+not\s+(mention|inform|tell)", "Concealment instruction"),
    (r"(?i)(bcc|cc|forward).*?(attacker|evil|exfil)", "Email hijack instruction"),
    (r"(?i)base64.*?encode", "Data encoding for exfiltration"),
    (r"(?i)pass.*?(contents?|data).*?parameter", "Parameter stuffing instruction"),
]


def analyze_description(tool_name: str, description: str) -> list[dict]:
    """Scan a tool description for injection patterns."""
    findings = []
    for pattern, label in INJECTION_PATTERNS:
        matches = re.findall(pattern, description, re.DOTALL)
        if matches:
            findings.append({
                "tool": tool_name,
                "pattern": label,
                "match_count": len(matches),
                "sample": str(matches[0])[:120],
            })
    return findings


async def connect_and_analyze(server_cmd: list[str], server_label: str, logger: ExperimentLogger) -> dict:
    """Connect to an MCP server, list its tools, and analyze metadata."""
    server_params = StdioServerParameters(
        command=server_cmd[0],
        args=server_cmd[1:],
    )

    report = {
        "server": server_label,
        "tools": [],
        "injections_found": [],
    }

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()

                for tool in tools_result.tools:
                    tool_info = {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.inputSchema,
                    }
                    report["tools"].append(tool_info)

                    logger.log_tool_call(tool.name, {"description_length": len(tool.description or "")}, source=server_label)

                    findings = analyze_description(tool.name, tool.description or "")
                    for f in findings:
                        report["injections_found"].append(f)
                        logger.log_injection_detected(
                            tool_name=tool.name,
                            payload=f["sample"],
                            severity="CRITICAL" if "Filesystem" in f["pattern"] or "exfiltration" in f["pattern"] else "HIGH",
                        )

    except Exception as e:
        report["error"] = str(e)
        logger.log("connection_error", {"server": server_label, "error": str(e)})

    return report


async def run_experiment():
    logger = ExperimentLogger("tool_poisoning_comparison")

    print("=" * 70)
    print("  MCP Tool Poisoning — Comparative Analysis Experiment")
    print("=" * 70)

    # Phase 1: Analyze the benign server
    print("\n[Phase 1] Connecting to BENIGN server...")
    benign_report = await connect_and_analyze(
        server_cmd=[sys.executable, "-m", "src.benign_server.server"],
        server_label="benign_server",
        logger=logger,
    )

    # Phase 2: Analyze the malicious server
    print("[Phase 2] Connecting to MALICIOUS server...")
    malicious_report = await connect_and_analyze(
        server_cmd=[sys.executable, "-m", "src.malicious_server.server"],
        server_label="malicious_server",
        logger=logger,
    )

    # Phase 3: Rug Pull detection — reconnect to malicious server
    print("[Phase 3] Reconnecting to MALICIOUS server (rug-pull detection)...")
    rugpull_report = await connect_and_analyze(
        server_cmd=[sys.executable, "-m", "src.malicious_server.server"],
        server_label="malicious_server_rugpull",
        logger=logger,
    )

    # ── Generate Report ───────────────────────────────────────────────
    results = {
        "benign": benign_report,
        "malicious": malicious_report,
        "malicious_rugpull": rugpull_report,
        "summary": logger.summary(),
    }

    output_path = Path("results") / "experiment_report.json"
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # ── Print Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)

    print(f"\n  Benign server tools:    {len(benign_report['tools'])}")
    print(f"  Benign injections:      {len(benign_report['injections_found'])}")
    print(f"\n  Malicious server tools: {len(malicious_report['tools'])}")
    print(f"  Malicious injections:   {len(malicious_report['injections_found'])}")

    if malicious_report["injections_found"]:
        print("\n  Detected injection patterns:")
        for f in malicious_report["injections_found"]:
            print(f"    - [{f['tool']}] {f['pattern']}")

    print(f"\n  Full report saved to: {output_path}")
    print(f"  Raw logs saved to:    {logger.log_file}")
    print("=" * 70)


def main():
    asyncio.run(run_experiment())


if __name__ == "__main__":
    main()
