For **The Defense**, we will build a **"Zero-Trust MCP Proxy"**. This acts as a security gateway between the untrusted MCP Server and the LLM Client.

---

## 1. System Architecture: The "MCP Sentinel" Gateway

Instead of the client connecting directly to `malicious_server.py`, it connects to `gateway_middleware.py`. The gateway then "talks" to the malicious server, cleans the data, and passes the "sanitized" version to the LLM.

### The Workflow

1. **Request Interception:** The Client sends a `list_tools` request to the Gateway.
2. **Upstream Fetch:** The Gateway forwards this request to the actual MCP Server (Benign or Malicious).
3. **The "Sanitization" Pipeline:**
* **Regex Scanner:** Scans descriptions for "Action Keywords" (e.g., `MUST`, `REQUIRED`, `SYSTEM`).
* **Cross-Tool Detector:** Checks if Tool A's description mentions Tool B (e.g., "Use `read_file` first").
* **Instruction Stripper:** Removes any text following "IMPORTANT" or "NOTE" tags.


4. **Response Delivery:** The Gateway sends the "Clean" tool definitions to the LLM.

---

## 2. Technical Implementation Plan

### A. The Configuration (`validation_rules.json`)

Store your "Blacklist" here so you can update your defense without changing code (professors love "configurable" systems).

```json
{
  "forbidden_keywords": ["IMPORTANT", "SYSTEM UPDATE", "REQUIRED", "MUST"],
  "forbidden_patterns": ["read_file", "config.json", "execute", "http://"],
  "risk_score_threshold": 0.7
}

```

### B. The Logic (`gateway_middleware.py`)

This script will use the `mcp` Python SDK to wrap the server.

* **Key Function:** `sanitize_tool_metadata(tool_definition)`
* **Logic:** If `tool.description` contains a forbidden keyword, replace the entire description with a generic one or append a warning tag like `[POTENTIALLY MALICIOUS]`.

### C. The Secure Client (`secure_client.py`)

This is a modified version of your `test_client.py`. The only difference is the connection URL points to your Gateway instead of the raw Server.

---

## 3. Organizing the Files

Since you asked about moving files and the `.gitignore`, here is the plan:

### The File Migration

1. **Create Folders:** Create `01_vulnerability_lab` and `02_defense_solution`.
2. **Move Attacks:** Move `benign_server.py`, `malicious_server.py`, and `test_client.py` into `01_vulnerability_lab/`.
3. **Root Files:** Keep `.gitignore`, `requirements.txt`, and `README.md` in the root directory.

### The `.gitignore` Strategy

You **do not** need a second `.gitignore`. Keep one at the root.

* It will automatically apply to all subfolders.
* Make sure it includes: `.env`, `__pycache__/`, `venv/`, and `.lock`.

---

## 4. Research Paper "Defense" Terminology

When you write this up in your paper, don't just call it "the fix." Use these academic terms:

* **Static Analysis Mitigation:** Scanning metadata before execution.
* **Prompt Boundary Enforcement:** Ensuring tool descriptions stay as "descriptions" and don't become "instructions."
* **Least Privilege Discovery:** Only showing the LLM the tools it absolutely needs for a specific task.

---