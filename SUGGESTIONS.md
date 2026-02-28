# Suggestions to Strengthen the Paper for Publication

## 1. Run Real LLM Experiments
Test with Claude, GPT-4, and Llama and report actual compliance rates (e.g., "Claude followed the hidden instruction in 4/5 trials"). This is the **single most impactful addition** — reviewers expect empirical evidence beyond static analysis.

## 2. Add an LLM-Based Semantic Scanner
Complement the regex scanner with a second LLM that analyzes tool descriptions for malicious intent. Compare detection rates: regex vs LLM vs combined. This strengthens the mitigation contribution.

## 3. Unicode/Steganographic Evasion (4th Attack Vector)
Add a 4th attack using zero-width Unicode characters or homoglyphs to hide instructions inside tool descriptions. Test whether the regex scanner misses them. This demonstrates the limitations of pattern-matching defenses.

## 4. Multi-Model Comparison Table
Test which LLMs are most/least susceptible to tool poisoning (Claude, GPT-4, Gemini, Llama 3). Reviewers value comparative evaluation across models.

## 5. MCP-SafetyBench Integration
Reference and compare results against the [MCP-SafetyBench](https://arxiv.org/html/2512.15163v1) benchmark to position the work within the broader evaluation landscape.

## 6. Formal Threat Modeling
Add a STRIDE or MITRE ATT&CK mapping for the three attack vectors. This adds rigor and makes the paper more appealing to security-focused venues.

## 7. Target Venues for Submission
- **USENIX Security** or **IEEE S&P** — top-tier security conferences
- **ACM CCS Workshop on AI Security (AISec)** — more accessible, focused on AI security
- **NDSS** — strong systems security venue
- **arXiv preprint** — fast-track to establish priority while preparing for peer review
