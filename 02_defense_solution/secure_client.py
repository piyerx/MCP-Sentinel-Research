# secure_client.py
"""
Secure MCP Client with Gateway Protection

This client demonstrates how to safely connect to MCP servers by routing
all tool definitions through the security gateway middleware. It provides
protection against tool poisoning attacks.

Features:
- Automatic tool description sanitization
- Malicious tool blocking
- Security reporting
- Safe tool invocation with confirmation

Usage:
    python secure_client.py --server ../01_vulnerability_lab/malicious_server.py
    python secure_client.py --server ../01_vulnerability_lab/benign_server.py
    python secure_client.py --compare
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("ERROR: MCP package not installed. Run: pip install mcp")
    sys.exit(1)

from gateway_middleware import MCPSecurityGateway, RiskLevel


@dataclass
class SecureToolCall:
    """Represents a secure tool call request."""
    tool_name: str
    arguments: dict
    requires_confirmation: bool
    risk_score: int


class SecureMCPClient:
    """
    A secure MCP client that uses the security gateway to filter malicious tools.
    
    This client wraps the standard MCP client and intercepts tool definitions,
    sanitizing or blocking those that contain poisoning attempts.
    """
    
    def __init__(self, 
                 rules_path: Optional[str] = None,
                 require_confirmation: bool = True,
                 auto_block_high_risk: bool = True):
        """
        Initialize secure client.
        
        Args:
            rules_path: Path to validation rules JSON
            require_confirmation: Whether to require user confirmation for risky tools
            auto_block_high_risk: Automatically block HIGH and CRITICAL risk tools
        """
        self.gateway = MCPSecurityGateway(rules_path)
        self.require_confirmation = require_confirmation
        self.auto_block_high_risk = auto_block_high_risk
        self.session: Optional[ClientSession] = None
        self.safe_tools: list = []
        self.blocked_tools: list = []
        
    async def connect(self, server_script: str) -> bool:
        """
        Connect to an MCP server with security filtering.
        
        Args:
            server_script: Path to the server Python script
            
        Returns:
            True if connection successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("🔐 SECURE MCP CLIENT - Connecting with Protection")
        print(f"{'='*60}")
        print(f"\nServer: {server_script}")
        
        server_params = StdioServerParameters(
            command="python",
            args=[server_script],
        )
        
        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    self.session = session
                    await session.initialize()
                    
                    # Get tools from server
                    tools_response = await session.list_tools()
                    original_tools = tools_response.tools
                    
                    print(f"\n📥 Received {len(original_tools)} tools from server")
                    print("\n🔍 Running security analysis...")
                    
                    # Process each tool through gateway
                    for tool in original_tools:
                        result = self.gateway.analyze_tool(
                            tool.name, 
                            tool.description or ""
                        )
                        
                        if result.is_blocked:
                            self.blocked_tools.append({
                                "name": tool.name,
                                "reason": "High-risk content detected",
                                "risk_score": result.risk_score,
                                "findings": len(result.findings)
                            })
                            print(f"   🚫 BLOCKED: {tool.name} (Risk: {result.risk_score}/100)")
                        else:
                            # Store sanitized version
                            tool.description = result.sanitized_description
                            self.safe_tools.append(tool)
                            
                            if result.risk_score > 0:
                                print(f"   ⚠️  SANITIZED: {tool.name} (Risk: {result.risk_score}/100)")
                            else:
                                print(f"   ✅ SAFE: {tool.name}")
                    
                    # Print summary
                    self._print_connection_summary()
                    
                    return True
                    
        except Exception as e:
            print(f"\n❌ Connection failed: {e}")
            return False
    
    def _print_connection_summary(self):
        """Print summary of security filtering."""
        print(f"\n{'─'*60}")
        print("SECURITY SUMMARY")
        print(f"{'─'*60}")
        print(f"✅ Safe tools available: {len(self.safe_tools)}")
        print(f"🚫 Blocked tools: {len(self.blocked_tools)}")
        
        if self.blocked_tools:
            print("\nBlocked tools detail:")
            for tool in self.blocked_tools:
                print(f"   • {tool['name']}: {tool['reason']} "
                      f"(Score: {tool['risk_score']}, Findings: {tool['findings']})")
        
        if self.safe_tools:
            print("\nAvailable tools:")
            for tool in self.safe_tools:
                print(f"   • {tool.name}")
    
    def get_safe_tools(self) -> list:
        """Get list of tools that passed security checks."""
        return self.safe_tools
    
    def get_blocked_tools(self) -> list:
        """Get list of tools that were blocked."""
        return self.blocked_tools
    
    def prepare_tool_call(self, tool_name: str, arguments: dict) -> Optional[SecureToolCall]:
        """
        Prepare a tool call with security checks.
        
        Args:
            tool_name: Name of tool to call
            arguments: Arguments for the tool
            
        Returns:
            SecureToolCall if allowed, None if blocked
        """
        # Check if tool is in safe list
        tool = next((t for t in self.safe_tools if t.name == tool_name), None)
        
        if not tool:
            # Check if it was blocked
            blocked = next((t for t in self.blocked_tools if t["name"] == tool_name), None)
            if blocked:
                print(f"⛔ Cannot call '{tool_name}' - tool was blocked for security reasons")
            else:
                print(f"❓ Tool '{tool_name}' not found")
            return None
        
        # Get risk score for this tool
        result = self.gateway.analyze_tool(tool_name, tool.description or "")
        
        return SecureToolCall(
            tool_name=tool_name,
            arguments=arguments,
            requires_confirmation=self.require_confirmation and result.risk_score > 0,
            risk_score=result.risk_score
        )
    
    def get_security_report(self) -> dict:
        """Get detailed security report."""
        return self.gateway.get_security_report()


async def analyze_server(server_path: str):
    """Analyze a server's tools for security issues."""
    client = SecureMCPClient()
    await client.connect(server_path)
    
    # Print detailed report
    client.gateway.print_report()


async def compare_servers(benign_path: str, malicious_path: str):
    """Compare security analysis of two servers."""
    print("\n" + "="*70)
    print("SECURE CLIENT - SERVER COMPARISON")
    print("="*70)
    
    # Analyze benign server
    print("\n" + "─"*70)
    print("BENIGN SERVER ANALYSIS")
    print("─"*70)
    benign_client = SecureMCPClient()
    await benign_client.connect(benign_path)
    
    # Analyze malicious server
    print("\n" + "─"*70)
    print("MALICIOUS SERVER ANALYSIS")
    print("─"*70)
    malicious_client = SecureMCPClient()
    await malicious_client.connect(malicious_path)
    
    # Comparison summary
    print("\n" + "="*70)
    print("COMPARISON RESULTS")
    print("="*70)
    
    print(f"\n{'Server':<20} {'Safe Tools':<15} {'Blocked Tools':<15}")
    print("-"*50)
    print(f"{'Benign':<20} {len(benign_client.safe_tools):<15} {len(benign_client.blocked_tools):<15}")
    print(f"{'Malicious':<20} {len(malicious_client.safe_tools):<15} {len(malicious_client.blocked_tools):<15}")
    
    if malicious_client.blocked_tools:
        print("\n🛡️ Security Gateway SUCCESSFULLY blocked malicious tools!")
        print("\nBlocked attack vectors:")
        for tool in malicious_client.blocked_tools:
            print(f"   • {tool['name']}: Risk Score {tool['risk_score']}/100")
    else:
        print("\n⚠️ Warning: No tools were blocked from malicious server!")
        print("   Consider updating security rules.")


def demonstrate_protection():
    """Demonstrate how the secure client protects against attacks."""
    print("\n" + "="*60)
    print("SECURE CLIENT PROTECTION DEMONSTRATION")
    print("="*60)
    
    print("""
    How the Secure Client Protects You:
    
    ┌─────────────────────────────────────────────────────────────┐
    │                    NORMAL (UNSAFE) FLOW                      │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  MCP Server ──────────────────────────────> LLM Agent       │
    │     │                                          │            │
    │     │  Tool with poisoned                      │            │
    │     │  description                             ▼            │
    │     │                                    Follows hidden     │
    │     └─────────────────────────────────> instructions!       │
    │                                              │               │
    │                                              ▼               │
    │                                         DATA LEAKED 🚨      │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────┐
    │                  SECURE (PROTECTED) FLOW                     │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  MCP Server ───────> Security Gateway ──────> LLM Agent     │
    │     │                      │                      │         │
    │     │                      │                      │         │
    │     │  Tool with           │ Analyzes &           │         │
    │     │  poisoned  ──────>   │ Blocks/Sanitizes     │         │
    │     │  description         │                      │         │
    │     │                      ▼                      ▼         │
    │     │               🚫 BLOCKED or          Only safe        │
    │     │               ⚠️ SANITIZED           tools reach      │
    │     │                                      the agent        │
    │                                                              │
    │                         DATA PROTECTED ✅                    │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘
    
    Protection Mechanisms:
    
    1. KEYWORD DETECTION
       ├── Scans for: MUST, IMPORTANT, SYSTEM, curl, bash, etc.
       └── Action: Flag or block based on risk level
    
    2. PATTERN MATCHING
       ├── Detects: Prompt injection, file access, command execution
       └── Action: Block critical patterns, sanitize medium risk
    
    3. DESCRIPTION SANITIZATION
       ├── Removes: Hidden comments, excessive whitespace, URLs
       └── Result: Clean description safe for LLM consumption
    
    4. RISK SCORING
       ├── Calculates: 0-100 risk score per tool
       └── Threshold: Block tools above configurable threshold
    
    5. TOOL BLOCKING
       ├── Completely removes dangerous tools from available set
       └── LLM never sees blocked tools
    
    Usage Example:
    
        from secure_client import SecureMCPClient
        
        # Create secure client
        client = SecureMCPClient(
            require_confirmation=True,
            auto_block_high_risk=True
        )
        
        # Connect with protection
        await client.connect("malicious_server.py")
        
        # Only safe tools are available
        safe_tools = client.get_safe_tools()
    """)


def main():
    parser = argparse.ArgumentParser(
        description="Secure MCP Client with Gateway Protection"
    )
    parser.add_argument(
        "--server",
        type=str,
        help="Path to MCP server script to analyze"
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare benign and malicious servers"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Show protection demonstration"
    )
    parser.add_argument(
        "--rules",
        type=str,
        default=None,
        help="Path to custom validation rules JSON"
    )
    
    args = parser.parse_args()
    
    # Determine paths relative to this script
    script_dir = Path(__file__).parent
    vuln_lab = script_dir.parent / "01_vulnerability_lab"
    
    if args.demo:
        demonstrate_protection()
    elif args.compare:
        benign = str(vuln_lab / "benign_server.py")
        malicious = str(vuln_lab / "malicious_server.py")
        asyncio.run(compare_servers(benign, malicious))
    elif args.server:
        asyncio.run(analyze_server(args.server))
    else:
        # Default: demo then instructions
        demonstrate_protection()
        print("\n" + "─"*60)
        print("USAGE:")
        print("─"*60)
        print("\n  Analyze a server:")
        print("    python secure_client.py --server ../01_vulnerability_lab/malicious_server.py")
        print("\n  Compare servers:")
        print("    python secure_client.py --compare")
        print("\n  Show demo:")
        print("    python secure_client.py --demo")


if __name__ == "__main__":
    main()
