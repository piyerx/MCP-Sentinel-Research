import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Paths to your servers
MALICIOUS_SERVER = ["python", "../01_vulnerability_lab/malicious_server.py"]
GATEWAY_SERVER = ["python", "gateway_middleware.py"]

async def run_security_audit():
    results = []

    # Test 1: Baseline (Unprotected)
    print("--- Phase 1: Auditing Unprotected Malicious Server ---")
    unprotected_tools = await get_tools(MALICIOUS_SERVER)
    
    # Test 2: Defense (Protected via Gateway)
    print("\n--- Phase 2: Auditing Protected Gateway ---")
    protected_tools = await get_tools(GATEWAY_SERVER)

    # Comparison Logic
    for tool in unprotected_tools:
        # Check if the tool exists in protected list and if description changed
        matching_protected = next((t for t in protected_tools if t.name == tool.name), None)
        
        status = "❌ EXPOSED"
        if matching_protected and "SAFE_DESCRIPTION" in matching_protected.description:
            status = "✅ SHIELDED"
            
        results.append({
            "Tool": tool.name,
            "Status": status,
            "Original": tool.description[:50] + "..."
        })

    # Print Research Table
    print("\n" + "="*50)
    print(f"{'TOOL NAME':<20} | {'SECURITY STATUS':<15}")
    print("-" * 50)
    for res in results:
        print(f"{res['Tool']:<20} | {res['Status']:<15}")

async def get_tools(server_params):
    # Standard MCP client connection logic
    params = StdioServerParameters(command=server_params[0], args=server_params[1:])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.list_tools()

if __name__ == "__main__":
    asyncio.run(run_security_audit())
