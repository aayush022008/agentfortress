# Compliance Guide

AgentShield supports GDPR, HIPAA, SOC 2, and EU AI Act compliance.

## GDPR
- Auto-detect PII in agent events (email, phone, SSN, etc.)
- Data residency validation (EU regions)
- Right-to-erasure request management

## HIPAA
- 18 Safe Harbor PHI identifiers
- Audit controls (§164.312(b))
- Access logging

## SOC 2
- All 5 Trust Services Criteria
- Control checklist with pass/fail per control
- Evidence collection

## EU AI Act
- Risk classification (Unacceptable/High/Limited/Minimal)
- Conformity assessment checklists
- Human oversight logging

## Running Checks

```bash
agentshield compliance check --frameworks gdpr,hipaa,soc2
agentshield compliance report --framework gdpr --format pdf
```
