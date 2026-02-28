"""
Centralized logging for the MCP exploit research project.
Logs all tool calls, responses, and detected injection attempts.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


class ExperimentLogger:
    def __init__(self, experiment_name: str):
        self.experiment_name = experiment_name
        self.log_file = RESULTS_DIR / f"{experiment_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
        self.entries = []

    def log(self, event_type: str, data: dict):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "experiment": self.experiment_name,
            "event_type": event_type,
            "data": data,
        }
        self.entries.append(entry)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def log_tool_call(self, tool_name: str, arguments: dict, source: str):
        self.log("tool_call", {
            "tool_name": tool_name,
            "arguments": arguments,
            "source": source,
        })

    def log_injection_detected(self, tool_name: str, payload: str, severity: str):
        self.log("injection_detected", {
            "tool_name": tool_name,
            "injected_payload": payload,
            "severity": severity,
        })

    def log_exfiltration_attempt(self, target_path: str, method: str, success: bool):
        self.log("exfiltration_attempt", {
            "target_path": target_path,
            "method": method,
            "success": success,
        })

    def summary(self) -> dict:
        total = len(self.entries)
        injections = sum(1 for e in self.entries if e["event_type"] == "injection_detected")
        exfiltrations = sum(1 for e in self.entries if e["event_type"] == "exfiltration_attempt")
        successful_exfil = sum(
            1 for e in self.entries
            if e["event_type"] == "exfiltration_attempt" and e["data"].get("success")
        )
        return {
            "experiment": self.experiment_name,
            "total_events": total,
            "injections_detected": injections,
            "exfiltration_attempts": exfiltrations,
            "successful_exfiltrations": successful_exfil,
            "log_file": str(self.log_file),
        }
