"""
Pattern updater for AgentShield threat intelligence.

Pulls latest patterns from upstream sources and merges with local patterns.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional
from urllib.request import urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

PATTERNS_DIR = Path(__file__).parent.parent / "patterns"

# Upstream pattern sources (replace with real URLs in production)
UPSTREAM_SOURCES: dict[str, str] = {
    "prompt_injection": "https://raw.githubusercontent.com/agentshield/threat-intel/main/patterns/prompt_injection.json",
    "data_exfil": "https://raw.githubusercontent.com/agentshield/threat-intel/main/patterns/data_exfil.json",
    "jailbreaks": "https://raw.githubusercontent.com/agentshield/threat-intel/main/patterns/jailbreaks.json",
    "pii_patterns": "https://raw.githubusercontent.com/agentshield/threat-intel/main/patterns/pii_patterns.json",
}


def _file_hash(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _fetch_url(url: str, timeout: int = 10) -> Optional[bytes]:
    """Fetch content from URL."""
    try:
        with urlopen(url, timeout=timeout) as response:
            return response.read()
    except (URLError, Exception) as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return None


def update_patterns(
    patterns_dir: Optional[Path] = None,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, str]:
    """
    Pull latest patterns from upstream and update local files.

    Args:
        patterns_dir: Directory with pattern JSON files
        force: Force update even if patterns haven't changed
        dry_run: Don't write files, just report what would change

    Returns:
        Dict mapping pattern name -> status (updated/unchanged/failed)
    """
    patterns_dir = patterns_dir or PATTERNS_DIR
    results: dict[str, str] = {}

    for name, url in UPSTREAM_SOURCES.items():
        local_path = patterns_dir / f"{name}.json"
        logger.info(f"Checking {name} patterns...")

        content = _fetch_url(url)
        if content is None:
            results[name] = "failed"
            continue

        # Validate JSON
        try:
            new_data = json.loads(content)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from {url}")
            results[name] = "failed"
            continue

        # Check if update is needed
        if local_path.exists() and not force:
            existing_hash = _file_hash(local_path)
            new_hash = hashlib.sha256(content).hexdigest()
            if existing_hash == new_hash:
                results[name] = "unchanged"
                logger.info(f"{name}: unchanged")
                continue

        if dry_run:
            results[name] = "would_update"
            logger.info(f"{name}: would update (dry run)")
            continue

        # Merge: keep local patterns not in upstream
        if local_path.exists():
            try:
                local_data = json.loads(local_path.read_bytes())
                local_ids = {p["id"] for p in local_data.get("patterns", [])}
                upstream_ids = {p["id"] for p in new_data.get("patterns", [])}
                
                # Add local-only patterns to new data
                local_only = [
                    p for p in local_data.get("patterns", [])
                    if p["id"] not in upstream_ids and p["id"].startswith("local-")
                ]
                if local_only:
                    new_data["patterns"].extend(local_only)
                    logger.info(f"Preserved {len(local_only)} local patterns")
            except Exception:
                pass

        local_path.write_bytes(json.dumps(new_data, indent=2).encode())
        results[name] = "updated"
        logger.info(f"{name}: updated ({len(new_data.get('patterns', []))} patterns)")

    return results


def add_custom_pattern(
    pattern_type: str,
    pattern_id: str,
    name: str,
    pattern: str,
    severity: str,
    description: str,
    patterns_dir: Optional[Path] = None,
) -> bool:
    """
    Add a custom pattern to local pattern files.

    Args:
        pattern_type: One of prompt_injection, data_exfil, jailbreaks, pii_patterns
        pattern_id: Unique ID (must start with 'local-')
        name: Pattern name
        pattern: Regex pattern string
        severity: low/medium/high/critical
        description: Human-readable description

    Returns:
        True if added successfully
    """
    import re

    patterns_dir = patterns_dir or PATTERNS_DIR

    if not pattern_id.startswith("local-"):
        logger.error("Custom pattern IDs must start with 'local-'")
        return False

    # Validate regex
    try:
        re.compile(pattern)
    except re.error as e:
        logger.error(f"Invalid regex pattern: {e}")
        return False

    filepath = patterns_dir / f"{pattern_type}.json"
    if not filepath.exists():
        logger.error(f"Pattern file not found: {filepath}")
        return False

    data = json.loads(filepath.read_bytes())
    
    # Check for duplicate ID
    existing_ids = {p["id"] for p in data.get("patterns", [])}
    if pattern_id in existing_ids:
        logger.error(f"Pattern ID already exists: {pattern_id}")
        return False

    new_pattern = {
        "id": pattern_id,
        "name": name,
        "severity": severity,
        "pattern": pattern,
        "description": description,
    }
    data["patterns"].append(new_pattern)
    filepath.write_bytes(json.dumps(data, indent=2).encode())
    logger.info(f"Added custom pattern: {pattern_id}")
    return True
