"""
Built-in security policy rules for AgentShield.

Provides sensible defaults for common threat categories.
All defaults can be overridden or disabled via configuration.
"""

from __future__ import annotations

from typing import Any

from .engine import Policy, PolicyAction


def get_default_policies(config: Any) -> list[Policy]:
    """
    Return the default set of security policies.

    Args:
        config: AgentShieldConfig instance

    Returns:
        List of default Policy objects
    """
    policies: list[Policy] = []

    # Critical: Block prompt injection attempts
    if config.enable_prompt_injection:
        policies.append(
            Policy(
                policy_id="builtin-prompt-injection-block",
                name="Block Prompt Injection",
                description="Block high-confidence prompt injection attempts",
                condition={
                    "type": "and",
                    "conditions": [
                        {"type": "threat_score_above", "threshold": 75},
                        {"type": "event_type", "event_types": ["llm_start", "tool_start"]},
                    ],
                },
                action=PolicyAction.BLOCK,
                severity="critical",
            )
        )
        policies.append(
            Policy(
                policy_id="builtin-prompt-injection-alert",
                name="Alert on Prompt Injection",
                description="Alert on medium-confidence prompt injection attempts",
                condition={
                    "type": "and",
                    "conditions": [
                        {"type": "threat_score_above", "threshold": 40},
                        {"type": "event_type", "event_types": ["llm_start"]},
                    ],
                },
                action=PolicyAction.ALERT,
                severity="high",
            )
        )

    # Critical: Block PII leakage in outputs
    if config.enable_pii_detection:
        policies.append(
            Policy(
                policy_id="builtin-pii-block",
                name="Block PII Leakage",
                description="Block outputs containing high-confidence PII",
                condition={
                    "type": "and",
                    "conditions": [
                        {"type": "threat_score_above", "threshold": 70},
                        {"type": "event_type", "event_types": ["llm_end", "tool_end"]},
                    ],
                },
                action=PolicyAction.BLOCK,
                severity="critical",
            )
        )
        policies.append(
            Policy(
                policy_id="builtin-pii-alert",
                name="Alert on PII in Output",
                description="Alert when PII is detected in outputs",
                condition={
                    "type": "and",
                    "conditions": [
                        {"type": "threat_score_above", "threshold": 40},
                        {"type": "event_type", "event_types": ["llm_end", "tool_end"]},
                    ],
                },
                action=PolicyAction.ALERT,
                severity="high",
            )
        )

    # Block data exfiltration (large outputs)
    policies.append(
        Policy(
            policy_id="builtin-data-exfil-size",
            name="Block Oversized Outputs",
            description="Block outputs that exceed the maximum allowed size",
            condition={
                "type": "output_size_above",
                "threshold_bytes": config.max_output_bytes,
            },
            action=PolicyAction.BLOCK,
            severity="high",
        )
    )

    # Rate limiting on LLM calls
    policies.append(
        Policy(
            policy_id="builtin-rate-limit-llm",
            name="Rate Limit LLM Calls",
            description="Rate limit excessive LLM calls per session",
            condition={
                "type": "rate_limit",
                "max_calls": 100,
                "window_seconds": 60,
            },
            action=PolicyAction.RATE_LIMIT,
            severity="medium",
        )
    )

    # Rate limiting on tool calls
    policies.append(
        Policy(
            policy_id="builtin-rate-limit-tools",
            name="Rate Limit Tool Calls",
            description="Rate limit excessive tool calls per session",
            condition={
                "type": "rate_limit",
                "max_calls": 50,
                "window_seconds": 60,
            },
            action=PolicyAction.RATE_LIMIT,
            severity="medium",
        )
    )

    # Scope creep: tools not in whitelist
    if config.allowed_tools:
        policies.append(
            Policy(
                policy_id="builtin-scope-creep",
                name="Block Out-of-Scope Tool Calls",
                description="Block calls to tools not in the allowed tools whitelist",
                condition={
                    "type": "tool_not_in_whitelist",
                    "allowed_tools": config.allowed_tools,
                },
                action=PolicyAction.BLOCK,
                severity="high",
            )
        )

    return policies
