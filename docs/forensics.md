# Forensics Guide

## Taking Snapshots

```bash
agentshield forensics snapshot --agent-id agent-001 --session-id sess-123
```

## Building Timelines

```bash
agentshield forensics timeline --incident-id INC-001 --start-time 1710000000
```

## Creating Evidence Packages

```bash
agentshield forensics package --investigator "alice" --description "Incident INC-001"
```

Evidence packages are sealed as `.tar.gz` archives with:
- `manifest.json` — SHA-256 inventory
- `items/` — all evidence files
- Chain of custody (Ed25519 signed)
