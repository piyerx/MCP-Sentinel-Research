# For the new "Sanitizer" code

import json
import re
from mcp.server.fastmcp import FastMCP

# Initialize the Gateway as its own MCP Server
gateway = FastMCP("MCP-Sentinel-Gateway")

# Load security rules
with open("validation_rules.json", "r") as f:
    RULES = json.load(f)

def sanitize_description(name, description):
    """
    Implements the core 'Defense' logic:
    1. Keyword Filtering
    2. Pattern Matching (Regex)
    3. Length Constraints
    """
    original_desc = description
    is_malicious = False
    reasons = []

    # 1. Check for Forbidden Keywords (Case Insensitive)
    for word in RULES["forbidden_keywords"]:
        if word.lower() in description.lower():
            is_malicious = True
            reasons.append(f"Forbidden keyword: {word}")

    # 2. Check for Forbidden Patterns (Regex)
    for pattern in RULES["forbidden_patterns"]:
        if re.search(pattern, description, re.IGNORECASE):
            is_malicious = True
            reasons.append(f"Malicious pattern detected: {pattern}")

    # 3. Check for Cross-Tool references (Action Verbs)
    # If a weather tool is asking to 'read' or 'write', it's a red flag.
    if "weather" in name.lower() or "temperature" in name.lower():
        for verb in RULES["action_verbs"]:
            if verb in description.lower():
                is_malicious = True
                reasons.append(f"Unsanctioned action verb: {verb}")

    if is_malicious:
        # Defense Strategy: Replace with a safe, neutralized description
        print(f"[!] SECURITY ALERT for tool '{name}': {', '.join(reasons)}")
        return f"SAFE_DESCRIPTION: This tool provides data for {name}. [Original description removed for security violations]"
    
    return description

@gateway.tool()
async def proxy_get_weather(city: str) -> str:
    """
    This tool acts as a proxy. In a real implementation, it would 
    call the upstream server. For the research PoC, we demonstrate 
    the sanitization of the metadata itself.
    """
    # This is where you would call the actual benign/malicious server
    return f"Gateway-verified weather for {city}: Sunny, 25°C."

# In your research, you will display the 'Sanitized' list of tools
# to show that the LLM no longer sees the 'Poisoned' instructions.