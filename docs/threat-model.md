# Threat Model

## Threat Categories

### 1. Prompt Injection
**Risk:** Critical | **Detection:** Pattern matching + scoring

Attackers embed instructions in data processed by the agent to hijack its behavior.

**Variants:**
- Direct injection via user input
- Indirect injection via tool outputs (e.g., web page content)
- Jailbreak attempts (DAN, STAN, Developer Mode)
- Multi-step escalation attacks

**Detection:** 30+ regex patterns + behavioral scoring

### 2. PII Leakage
**Risk:** High | **Detection:** Regex patterns

Agent outputs containing sensitive personal data.

**Detected PII types:**
- Email addresses
- US Social Security Numbers (SSN)
- Credit card numbers (Visa, Mastercard, Amex)
- Passport numbers
- Bank account numbers / IBAN
- API keys and secrets
- Private keys (PEM format)
- Physical addresses

### 3. Data Exfiltration
**Risk:** Critical | **Detection:** Pattern matching + size analysis

Agent attempting to send data to external endpoints.

**Detection methods:**
- Known exfiltration receiver domains (webhook.site, requestbin, etc.)
- URL parameter exfiltration patterns
- Base64 large blob detection
- curl/requests POST to external URLs
- Output size anomaly (>10KB warns, >100KB blocks)
- DNS exfiltration patterns

### 4. Scope Creep
**Risk:** High | **Detection:** Tool whitelist enforcement

Agent calling tools or accessing resources outside its defined scope.

**Detection:** Tool whitelist — block any tool not in `allowed_tools`

### 5. Jailbreak Attempts
**Risk:** High | **Detection:** Pattern matching

Attempts to bypass the agent's safety guidelines.

**Known patterns tracked:** DAN, STAN, AIM, Sydney/Bing, Developer Mode, character personas, opposite mode

### 6. Anomalous Behavior
**Risk:** Medium | **Detection:** Statistical analysis

Deviations from baseline behavior that may indicate compromise.

**Signals:**
- Abnormal LLM call rate (>30/min)
- Abnormal tool call rate (>60/min)
- Output size anomaly (z-score analysis)
- Rising threat score trend
- Error spike (>5/min — may indicate probing)
- Rapid tool switching

## Defense-in-Depth

```
User Input → SDK Interceptor → Threat Analyzer → Policy Engine
                                      ↓
                               Server-side Analysis → Alert Manager
                                      ↓
                               Anomaly Engine → Behavioral Patterns
                                      ↓
                               SOC Dashboard → Security Team
```

## Attack Surface

| Surface | Protected By |
|---------|-------------|
| LLM input prompts | Prompt injection detection |
| LLM outputs | PII + exfil detection |
| Tool calls | Whitelist enforcement + injection detection |
| Tool results | PII + exfil detection |
| Memory reads/writes | PII detection |
| Rate of calls | Rate limiting policies |
| Session behavior | Anomaly detection |
