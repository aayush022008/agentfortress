# Contributing to AgentShield

## Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/yourusername/agentshield
cd agentshield

# Install everything
make setup

# Start dev environment
make dev
```

## Project Structure

```
agentshield/
├── sdk/          — Python SDK (agentshield-sdk)
├── server/       — FastAPI backend
├── dashboard/    — React SOC dashboard
├── cli/          — Click CLI tool
├── threat-intel/ — Pattern libraries + matching engine
├── tests/        — Test suite
├── docs/         — Documentation
└── infra/        — Docker + Kubernetes
```

## Code Standards

- **Python:** Type hints everywhere, docstrings on public functions
- **TypeScript:** Strict mode, no `any` types
- **Tests:** All new features need tests
- **Patterns:** New threat patterns go in `threat-intel/patterns/*.json`

## Adding a New Threat Pattern

1. Determine the pattern type (prompt_injection, data_exfil, jailbreak, pii)
2. Add to `threat-intel/patterns/<type>.json`
3. Use ID format: `pi-NNN`, `de-NNN`, `jb-NNN`, `pii-NNN`
4. Custom local patterns use `local-NNN` prefix
5. Add a test in `tests/threat-intel/test_patterns.py`

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Write tests first
3. Implement the feature
4. Run `make test` and `make lint`
5. Submit PR with description of changes

## License

MIT
