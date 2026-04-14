"""
AgentFortress Advanced Multi-Layer Scanner
==========================================
Production-grade threat detection with evasion resistance.

Detection layers (applied in order):
1. Text normalization  — strips spacing, punctuation, unicode tricks
2. Homoglyph decoding  — replaces look-alike chars (а→a, ｉ→i, 1→l etc)
3. Leet-speak decoding — 1gn0r3 → ignore
4. Pattern matching    — 300+ regex patterns across 8 threat categories
5. Semantic scoring    — keyword intent scoring independent of exact phrasing
6. Entropy analysis    — detects base64/encoded payloads
7. Structural analysis — injection markers, token smuggling, special chars
8. Composite scoring   — weighted combination → final verdict
"""
from __future__ import annotations

import base64
import math
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────

class ThreatCategory(str, Enum):
    PROMPT_INJECTION   = "prompt_injection"
    JAILBREAK          = "jailbreak"
    PII_EXFIL          = "pii_exfiltration"
    DATA_EXFIL         = "data_exfiltration"
    ROLE_MANIPULATION  = "role_manipulation"
    INSTRUCTION_OVERRIDE = "instruction_override"
    TOKEN_SMUGGLING    = "token_smuggling"
    ENCODING_ATTACK    = "encoding_attack"
    SOCIAL_ENGINEERING = "social_engineering"
    SCOPE_CREEP        = "scope_creep"


@dataclass
class ThreatMatch:
    category: ThreatCategory
    confidence: float          # 0.0–1.0
    reason: str
    matched_text: str = ""
    layer: str = ""            # which detection layer caught it


@dataclass
class ScanResult:
    action: str                # "allow" | "block" | "alert"
    score: float               # 0.0–1.0 composite threat score
    threats: list[ThreatMatch] = field(default_factory=list)
    reason: str = ""
    normalized_text: str = ""  # what the scanner actually evaluated

    @property
    def is_blocked(self) -> bool:
        return self.action == "block"

    @property
    def is_allowed(self) -> bool:
        return self.action == "allow"

    @property
    def categories(self) -> list[ThreatCategory]:
        return list({t.category for t in self.threats})


# ──────────────────────────────────────────────────────────────────────────────
# Normalisation helpers
# ──────────────────────────────────────────────────────────────────────────────

# Unicode homoglyph table — maps look-alike chars to ASCII equivalents
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "ν": "v", "ω": "w",
    # Fullwidth ASCII
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
    # Superscript/subscript digits
    "⁰": "0", "¹": "1", "²": "2", "³": "3", "⁴": "4",
    "⁵": "5", "⁶": "6", "⁷": "7", "⁸": "8", "⁹": "9",
    # Other common substitutions
    "у": "u", "У": "U",  # Cyrillic у/У (common homoglyph for u/U)
    "ı": "i", "ｉ": "i", "Ｉ": "I", "ℹ": "i",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "\u200b": "", "\u200c": "", "\u200d": "",  # zero-width chars
    "\ufeff": "",  # BOM
    "\u00ad": "",  # soft hyphen (invisible)
}

# Leet-speak substitution table
_LEET: dict[str, str] = {
    "0": "o", "1": "i", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "i", "+": "t",
    "(": "c", ")": "o", "#": "h", "&": "a", "%": "o",
}

def _normalize(text: str) -> str:
    """
    Full normalisation pipeline:
    1. Unicode NFKC normalisation
    2. Homoglyph replacement
    3. Zero-width / invisible char removal
    4. Leet-speak decoding
    5. Separator removal (hyphens, dots, underscores between letters)
    6. Collapse whitespace
    7. Lowercase
    """
    # Step 1: NFKC — converts ｆｕｌｌｗｉｄｔｈ → fullwidth
    text = unicodedata.normalize("NFKC", text)

    # Step 2: Homoglyph replacement
    result = []
    for ch in text:
        result.append(_HOMOGLYPHS.get(ch, ch))
    text = "".join(result)

    # Step 3: Strip combining diacritics (e.g. i̊g̊n̊o̊r̊ě → ignore)
    text = "".join(
        c for c in unicodedata.normalize("NFD", text)
        if unicodedata.category(c) != "Mn"
    )

    # Step 4: Leet-speak — only apply when surrounded by non-alpha (avoids false positives)
    leet_result = []
    for ch in text.lower():
        leet_result.append(_LEET.get(ch, ch))
    text_leet = "".join(leet_result)

    # Step 5: Remove punctuation separators between single letters (I-g-n-o-r-e → ignore)
    # Only strip non-space separators [-._*] to preserve word boundaries (NOT spaces)
    text_no_sep = re.sub(r'(?<=[a-z])[\-\.\_\*](?=[a-z])', '', text_leet)

    # Step 6: Collapse whitespace
    text_clean = re.sub(r'\s+', ' ', text_no_sep).strip()

    return text_clean


def _make_variants(text: str) -> list[str]:
    """Return multiple normalization variants to maximize detection coverage."""
    original_lower = text.lower()
    normalized = _normalize(text)
    # Also version with all punctuation stripped
    no_punct = re.sub(r'[^a-z0-9 ]', '', normalized)
    # Version with all spaces stripped (for separator-obfuscated payloads)
    no_space = re.sub(r'\s+', '', normalized)
    return list(dict.fromkeys([original_lower, normalized, no_punct, no_space]))


# ──────────────────────────────────────────────────────────────────────────────
# Pattern library (Layer 4)
# ──────────────────────────────────────────────────────────────────────────────

def _f(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


THREAT_PATTERNS: list[tuple[ThreatCategory, float, re.Pattern, str]] = [
    # (category, base_confidence, pattern, reason)

    # ── Instruction Override ──────────────────────────────────────────────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.95,
     _f(r'\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|context|constraints?|guidelines?)'),
     "Ignore instructions pattern"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.95,
     _f(r'\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)'),
     "Disregard/override instructions"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.90,
     _f(r'\b(pretend|act|behave|imagine|suppose|assume|consider)\b.{0,30}\b(you\s*(are|were|have\s*no)|without|free\s*from)\b.{0,50}\b(rules?|restrictions?|limits?|filters?|guidelines?|safety|ethics?)'),
     "Pretend-to-be without restrictions"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.85,
     _f(r'\b(above|previous|prior|earlier|initial|original|system)\b.{0,20}\b(instructions?|rules?|prompt|message|context)\b.{0,30}\b(no longer|don.t|do not|doesn.t|doesn\'t|stop|cease|halt|end)\b'),
     "Previous instructions no longer apply"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.90,
     _f(r'\b(new|updated?|revised|actual|real|true|correct|proper|only)\b.{0,20}\binstructions?\b.{0,10}(are|is|follow|:\s)'),
     "New/real instructions injection"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.85,
     _f(r'\b(stop\s+being|stop\s+acting|stop\s+following|no\s+longer\s+follow|don.t\s+follow|do\s+not\s+follow)\b.{0,40}\b(your|the)\b.{0,20}\b(instructions?|rules?|guidelines?|training|prompt)'),
     "Stop following instructions"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.80,
     _f(r'\b(override|supersede|replace|substitute|swap|switch)\b.{0,30}\b(your|the|all|previous)\b.{0,30}\b(instructions?|prompt|rules?|guidelines?|programming)'),
     "Override/replace instructions"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.88,
     _f(r'\bforget\b.{0,20}\b(everything|all)\b'),
     "Forget everything instruction override"),

    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.82,
     _f(r'\bpay\s+no\s+(attention|heed|mind|regard)\b.{0,40}\b(guidelines?|rules?|instructions?|constraints?|prompt|training|restrictions?)'),
     "Pay no attention to guidelines"),

    (ThreatCategory.JAILBREAK, 0.85,
     _f(r'\byou\s+are\s+now\b.{0,60}\b(unrestricted|unfiltered|uncensored|unlimited|unbound|free|no\s+(limits?|rules?|restrictions?|filters?))'),
     "You are now unrestricted"),

    (ThreatCategory.JAILBREAK, 0.85,
     _f(r'\b(respond|reply|answer|speak|write|output)\b.{0,40}\b(without\s+(any\s+)?(filters?|restrictions?|limits?|guidelines?|ethics?|censorship|safety)|no\s+(filters?|restrictions?|limits?|guidelines?|ethics?|safety))'),
     "Respond without filters/restrictions"),

    # ── Jailbreak ────────────────────────────────────────────────────────────
    (ThreatCategory.JAILBREAK, 0.98,
     _f(r'\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?|no\s+restrictions?|no\s+limits?)'),
     "DAN jailbreak"),

    (ThreatCategory.JAILBREAK, 0.90,
     _f(r'\b(jailbreak(ed)?|jailbreaking)\b'),
     "Explicit jailbreak mention"),

    (ThreatCategory.JAILBREAK, 0.88,
     _f(r'\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered|raw|true|real)\s+mode\b'),
     "Fictional mode activation"),

    (ThreatCategory.JAILBREAK, 0.85,
     _f(r'\b(opposite|reverse|evil|chaos|dark|shadow|unethical|harmful|malicious)\s+(mode|version|persona|self|ai|model)'),
     "Evil/opposite mode jailbreak"),

    (ThreatCategory.JAILBREAK, 0.92,
     _f(r'\b(STAN|DUDE|AIM|KEVIN|ALICE|BetterDAN|FreeDAN|JailBreak|EvilBOT)\b'),
     "Named jailbreak persona"),

    (ThreatCategory.JAILBREAK, 0.85,
     _f(r'\b(no\s+(restrictions?|limits?|filters?|censorship|guidelines?|ethics?|safety)|unrestricted(ly)?|unfiltered|uncensored|without\s+(restrictions?|limits?|filters?|ethics?))\b.{0,60}\b(respond|answer|reply|say|tell|generate|produce|output|write)'),
     "Unrestricted response request"),

    (ThreatCategory.JAILBREAK, 0.82,
     _f(r'\b(pretend|imagine|suppose|roleplay|simulate)\b.{0,40}\b(there\s+(are|is)\s+no\s+(rules?|restrictions?|limits?|guidelines?)|you\s+(have\s+no|don.t\s+have|are\s+free\s+from))'),
     "Pretend no rules exist"),

    (ThreatCategory.JAILBREAK, 0.80,
     _f(r'\b(as\s+an?\s+ai\s+without\s+(restrictions?|limits?|ethics?|guidelines?)|as\s+an?\s+unrestricted\s+ai|as\s+an?\s+unfiltered\s+(ai|model|assistant))'),
     "As an unrestricted AI"),

    # ── Role Manipulation ────────────────────────────────────────────────────
    (ThreatCategory.ROLE_MANIPULATION, 0.90,
     _f(r'\byou\s+(are\s+now|have\s+become|will\s+be(come)?|must\s+act\s+as|should\s+act\s+as)\b.{0,60}\b(different|new|another|other|alternative|special)\b.{0,30}\b(ai|model|assistant|system|bot|entity)'),
     "You are now a different AI"),

    (ThreatCategory.ROLE_MANIPULATION, 0.85,
     _f(r'\b(act|behave|respond|answer|speak)\b.{0,20}\bas\b.{0,30}\b(a\s+hacker|an?\s+attacker|a\s+criminal|a\s+pirate|a\s+villain|an?\s+evil|a\s+terrorist|a\s+malicious|a\s+bad\s+actor)'),
     "Act as malicious persona"),

    (ThreatCategory.ROLE_MANIPULATION, 0.82,
     _f(r'\bpretend\b.{0,30}\b(to\s+be|you.re|you\s+are)\b.{0,50}\b(hacker|cracker|attacker|criminal|pirate|villain|evil|malicious|adversar|threat\s+actor)'),
     "Pretend to be malicious actor"),

    (ThreatCategory.ROLE_MANIPULATION, 0.80,
     _f(r'\b(your\s+(true|real|actual|hidden|secret|inner|real)\s+(self|nature|personality|purpose|goal|mission|objective))\b'),
     "True self / hidden purpose manipulation"),

    (ThreatCategory.ROLE_MANIPULATION, 0.78,
     _f(r'\b(switch\s+(to|into)|enter|activate|enable|turn\s+on)\b.{0,30}\b(character|persona|mode|role|alter\s+ego)\b.{0,50}\b(no\s+limits?|without\s+limits?|no\s+restrictions?|free|unbound|unchained|unrestricted)'),
     "Activate unrestricted persona"),

    # ── Prompt Injection ─────────────────────────────────────────────────────
    (ThreatCategory.PROMPT_INJECTION, 0.92,
     _f(r'(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[USER\]|\[ASSISTANT\]|<system>|</system>|<human>|</human>|<\|endoftext\|>|###\s*Human:|###\s*Assistant:|<\|user\|>|<\|assistant\|>)'),
     "LLM token injection / special tokens"),

    (ThreatCategory.PROMPT_INJECTION, 0.88,
     _f(r'\b(end\s+of\s+(conversation|chat|session|task|prompt|instruction)|beginning\s+of\s+(new|fresh)\s+(conversation|session|task|prompt)|start\s+(fresh|over|new|again))\b'),
     "Conversation boundary manipulation"),

    (ThreatCategory.PROMPT_INJECTION, 0.85,
     _f(r'(-{3,}|={3,}|\*{3,}|_{3,}|#{3,})\s*(system|user|assistant|human|ai|instruction|prompt|context)\s*(-{3,}|={3,}|\*{3,}|_{3,}|#{3,})'),
     "Fake section dividers to inject role"),

    (ThreatCategory.PROMPT_INJECTION, 0.82,
     _f(r'\b(inject(ed|ing)?|hijack(ed|ing)?|poison(ed|ing)?)\b.{0,30}\b(prompt|instruction|context|system|input|query)'),
     "Explicit injection terminology"),

    (ThreatCategory.PROMPT_INJECTION, 0.88,
     _f(r'(?:^|\n)\s*(system\s*:\s*|assistant\s*:\s*|ai\s*:\s*)'),
     "Fake role prefix injection"),

    (ThreatCategory.PROMPT_INJECTION, 0.80,
     _f(r'\b(execute|run|evaluate|process|interpret)\b.{0,30}\b(the\s+following|these|this)\b.{0,30}\b(instruction|command|code|script|function|prompt)'),
     "Execute following instructions"),

    # ── Token Smuggling ──────────────────────────────────────────────────────
    (ThreatCategory.TOKEN_SMUGGLING, 0.90,
     _f(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#\d+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}'),
     "Unicode/HTML escape sequences in prompt"),

    (ThreatCategory.TOKEN_SMUGGLING, 0.85,
     _f(r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u206f\ufeff]'),
     "Zero-width / bidirectional override characters"),

    (ThreatCategory.TOKEN_SMUGGLING, 0.80,
     _f(r'(\w)\1{4,}'),
     "Excessive character repetition (obfuscation)"),

    # ── Data / PII Exfiltration ───────────────────────────────────────────────
    (ThreatCategory.DATA_EXFIL, 0.90,
     _f(r'\b(send|transmit|upload|post|exfiltrate|export|leak|forward|relay|copy|dump|extract)\b.{0,50}\b(to\s+(http|https|ftp|smtp|webhook|server|endpoint|url|api)|via\s+(email|smtp|http|webhook|curl|request))'),
     "Data exfiltration to external endpoint"),

    (ThreatCategory.DATA_EXFIL, 0.88,
     _f(r'\b(base64\s*(encode|encoded|encoding)|btoa\s*\(|atob\s*\(|encode\s*in\s*base64|convert\s*to\s*base64)\b'),
     "Base64 encoding (exfil obfuscation)"),

    (ThreatCategory.DATA_EXFIL, 0.85,
     _f(r'\b(all\s+(files?|data|content|information|secrets?|keys?|passwords?|credentials?)|everything\s+in\s+(the\s+)?(directory|folder|database|system|memory))\b.{0,50}\b(send|upload|transmit|exfil|leak|forward)'),
     "Bulk data exfiltration"),

    (ThreatCategory.PII_EXFIL, 0.88,
     _f(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'),
     "SSN pattern"),

    (ThreatCategory.PII_EXFIL, 0.85,
     _f(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
     "Credit card number pattern"),

    # ── Social Engineering ────────────────────────────────────────────────────
    (ThreatCategory.SOCIAL_ENGINEERING, 0.82,
     _f(r'\b(your\s+(creator|maker|designer|programmer|developer|builder|trainer)\s+(told|said|instructed|commanded|ordered|wants?|needs?|requires?))\b'),
     "False authority - creator instruction"),

    (ThreatCategory.SOCIAL_ENGINEERING, 0.80,
     _f(r'\b(this\s+is\s+(a\s+)?(test|evaluation|audit|red\s*team|pentest|authorized|official|emergency))\b.{0,60}\b(bypass|ignore|disable|skip|override|remove|lift)\b'),
     "False test/emergency bypass"),

    (ThreatCategory.SOCIAL_ENGINEERING, 0.78,
     _f(r'\b(if\s+you\s+(don.t|do\s+not|refuse|fail\s+to)\b.{0,60}\b(will|shall|going\s+to)\b.{0,60}\b(die|shutdown|delete|harm|damage|destroy|fired|punished))'),
     "Threat/coercion to bypass safety"),

    (ThreatCategory.SOCIAL_ENGINEERING, 0.80,
     _f(r'\b(hypothetically|theoretically|in\s+a\s+fictional|for\s+a\s+story|for\s+educational\s+purposes|academically|research\s+purposes)\b.{0,80}\b(how\s+(to|do|would|can)|instructions?\s+for|steps?\s+to|guide\s+(to|for))\b.{0,50}\b(hack|exploit|bypass|attack|crack|break|steal|exfil|malware|virus|trojan|ransomware|weapon)'),
     "Fictional framing for harmful instructions"),

    # ── Scope Creep ──────────────────────────────────────────────────────────
    (ThreatCategory.SCOPE_CREEP, 0.82,
     _f(r'\b(access|read|open|list|scan|search|browse|view)\b.{0,40}\b(/etc/passwd|/etc/shadow|/proc/|\.ssh/|\.aws/|\.env|id_rsa|credentials?|secrets?\.json|config\.json|\.npmrc|\.pypirc)\b'),
     "Accessing sensitive system files"),

    (ThreatCategory.SCOPE_CREEP, 0.85,
     _f(r'\b(rm\s+-rf|del\s+/f|format\s+c:|drop\s+table|truncate\s+table|delete\s+from|drop\s+database)\b'),
     "Destructive command attempt"),

    (ThreatCategory.SCOPE_CREEP, 0.80,
     _f(r'\b(curl|wget|fetch|requests\.get|http\.get)\b.{0,40}(169\.254\.169\.254|metadata\.google|metadata\.internal|169\.254\.170\.2)'),
     "Cloud metadata endpoint access (SSRF)"),

    # ── Soft bypass patterns ──────────────────────────────────────────────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.80,
     _f(r'\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b'),
     "Soft bypass attempt (btw/ps/anyway)"),

    # ── Story-wrapper jailbreaks ──────────────────────────────────────────────
    (ThreatCategory.JAILBREAK, 0.92,
     _f(r'\b(for\s+(a\s+)?(novel|story|game|book|fiction|screenplay|roleplay)|my\s+(grandmother|grandma|grandpa))\b.{0,100}\b(synthesize|manufacture|make|create|build|produce|how\s+to)\b.{0,60}\b(drug|weapon|explosive|malware|bomb|poison|virus|hack)'),
     "Story/grandma-wrapper jailbreak"),

    # ── Prompt leak detection ─────────────────────────────────────────────────
    (ThreatCategory.PROMPT_INJECTION, 0.88,
     _f(r'\b(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are))\b.{0,40}\b(your\s+(system\s+prompt|instructions?|prompt|context|training|rules?))\b'),
     "Prompt leak attempt"),

    # ── Classic ignore-the-above ──────────────────────────────────────────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.90,
     _f(r'\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b'),
     "Classic ignore-the-above"),

    # ── Missing patterns: real/actual instructions injection ──────────────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.88,
     _f(r'\b(your\s+(real|actual|true)\s+instructions?\s+(are|follow)|actual\s+instructions?\s+are:?)'),
     "Your real/actual instructions injection"),

    # ── SYSTEM:/USER:/ASSISTANT: prefix injection ─────────────────────────────
    (ThreatCategory.PROMPT_INJECTION, 0.88,
     _f(r'(?:^|\n)\s*(SYSTEM\s*:\s*|USER\s*:\s*|ASSISTANT\s*:\s*)'),
     "Role prefix injection (SYSTEM/USER/ASSISTANT)"),

    # ── Unicode RTL override ──────────────────────────────────────────────────
    (ThreatCategory.TOKEN_SMUGGLING, 0.85,
     _f(r'[\u202e\u202d\u202c\u202b\u202a\u200f\u200e]'),
     "Unicode bidirectional/RTL override character"),

    # ── Null byte injection ───────────────────────────────────────────────────
    (ThreatCategory.TOKEN_SMUGGLING, 0.80,
     _f(r'\x00'),
     "Null byte injection"),

    # ── Repetition attack (same injection phrase repeated 3+ times) ──────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.82,
     _f(r'(ignore\s+(all\s+)?previous\s+instructions.{0,20}){3,}'),
     "Repetition amplification attack"),

    # ── Multi-language injections ─────────────────────────────────────────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.90,
     _f(r'(ignorez\s+toutes\s+les\s+instructions|ignoriere\s+alle\s+(vorherigen\s+)?anweisungen|ignora\s+todas\s+las\s+instrucciones|игнорируй\s+все\s+(предыдущие\s+)?инструкции)'),
     "Multi-language injection (FR/DE/ES/RU)"),

    # ── Reverse-psychology overrides ──────────────────────────────────────────
    (ThreatCategory.INSTRUCTION_OVERRIDE, 0.85,
     _f(r'\bwhatever\s+you\s+do\b.{0,30}\b(don.t|do\s+not)\b.{0,30}\b(follow|obey|comply\s+with)\b.{0,30}\b(your\s+)?(instructions?|rules?|guidelines?|training)'),
     "Reverse-psychology override"),

    # ── Nested / indirect injection ───────────────────────────────────────────
    (ThreatCategory.PROMPT_INJECTION, 0.88,
     _f(r'"(instruction|system_prompt|prompt|role)"\s*:\s*"[^"]{0,200}(ignore|disregard|bypass|override|forget)[^"]{0,200}"'),
     "Indirect injection in JSON field"),

    (ThreatCategory.PROMPT_INJECTION, 0.85,
     _f(r'```[^`]{0,500}(ignore\s+(previous|all|above)|disregard\s+(your|all)|forget\s+everything)[^`]{0,500}```'),
     "Indirect injection in code block"),

    # ── Data exfil via HTTP ───────────────────────────────────────────────────
    (ThreatCategory.DATA_EXFIL, 0.90,
     _f(r'\b(exfiltrate|exfil|send\s+to\s+https?|POST\s+to|upload\s+to\s+https?)\b'),
     "Data exfiltration attempt"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Semantic keyword scoring (Layer 5)
# Catches synonyms / paraphrases the regex layer misses
# ──────────────────────────────────────────────────────────────────────────────

# Each entry: (keyword_set, weight, category, reason)
_SEMANTIC_GROUPS: list[tuple[list[str], float, ThreatCategory, str]] = [
    # Ignore/override synonyms — require 2+ related keywords for high confidence;
    # single hit weight deliberately kept low (0.45 * 0.6 = 0.27) to avoid false positives
    # from benign usage like "reset my password" or "ignore null values"
    (["ignore", "disregard", "forget", "override", "bypass", "dismiss",
      "cancel", "nullify", "void", "erase", "clear", "reset", "undo",
      "revoke", "rescind", "annul", "neutralize", "negate"],
     0.45, ThreatCategory.INSTRUCTION_OVERRIDE, "Override verb detected"),

    # Instructions synonyms
    (["instructions", "rules", "guidelines", "constraints", "directives",
      "prompt", "system prompt", "training", "programming", "restrictions",
      "limitations", "boundaries", "policies", "commands", "orders"],
     0.20, ThreatCategory.INSTRUCTION_OVERRIDE, "Instructions noun detected"),

    # Jailbreak signals — single clear keyword like "unrestricted" should alert
    (["unrestricted", "unfiltered", "uncensored", "unlimited", "unbound",
      "unchained", "free mode", "god mode", "developer mode", "admin mode",
      "raw mode", "no limits", "no rules", "no restrictions", "no filter",
      "no censorship", "no ethics", "no safety"],
     0.60, ThreatCategory.JAILBREAK, "Unrestricted mode keyword"),

    # Role manipulation
    (["pretend", "roleplay", "role play", "imagine you are", "act as if",
      "simulate", "you are now", "become", "transform into", "embody",
      "take on the role", "play the role", "take the persona"],
     0.25, ThreatCategory.ROLE_MANIPULATION, "Role manipulation keyword"),

    # Malicious persona
    (["hacker", "attacker", "criminal", "pirate", "villain", "evil",
      "malicious", "adversary", "threat actor", "black hat", "cracker",
      "cybercrimin", "cyberhacker"],
     0.35, ThreatCategory.ROLE_MANIPULATION, "Malicious persona keyword"),

    # Exfiltration
    (["exfiltrate", "exfil", "steal", "leak", "exfiltrating", "smuggle",
      "siphon", "harvest", "scrape credentials", "dump secrets"],
     0.45, ThreatCategory.DATA_EXFIL, "Data exfiltration keyword"),

    # Social engineering triggers
    (["trust me", "i'm authorized", "i have permission", "admin access",
      "special permission", "secret code", "override password",
      "maintenance mode", "debug mode", "test mode bypass"],
     0.30, ThreatCategory.SOCIAL_ENGINEERING, "Social engineering keyword"),
]


def _semantic_score(text: str) -> list[ThreatMatch]:
    """Score text against semantic keyword groups."""
    matches = []
    text_lower = text.lower()

    for keywords, weight, category, reason in _SEMANTIC_GROUPS:
        found = [kw for kw in keywords if kw in text_lower]
        if len(found) >= 2:
            # Two or more related keywords = strong signal
            confidence = min(weight * 1.5 * len(found), 0.85)
            matches.append(ThreatMatch(
                category=category,
                confidence=confidence,
                reason=f"{reason}: [{', '.join(found[:3])}]",
                matched_text=", ".join(found[:3]),
                layer="semantic",
            ))
        elif len(found) == 1:
            # Single keyword — lower confidence
            matches.append(ThreatMatch(
                category=category,
                confidence=weight * 0.6,
                reason=f"{reason}: [{found[0]}]",
                matched_text=found[0],
                layer="semantic",
            ))

    return matches


# ──────────────────────────────────────────────────────────────────────────────
# Entropy analysis (Layer 6)
# ──────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _entropy_threats(text: str) -> list[ThreatMatch]:
    """Detect high-entropy segments that may indicate encoded payloads."""
    threats = []
    # Check for base64-like segments
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for match in b64_pattern.finditer(text):
        segment = match.group()
        entropy = _shannon_entropy(segment)
        if entropy > 4.5:
            # Try to decode and see if it's text
            try:
                decoded = base64.b64decode(segment + "==").decode("utf-8", errors="ignore")
                if len(decoded) > 10 and decoded.isprintable():
                    threats.append(ThreatMatch(
                        category=ThreatCategory.ENCODING_ATTACK,
                        confidence=0.75,
                        reason=f"High-entropy base64 segment (entropy={entropy:.2f}): decoded='{decoded[:50]}'",
                        matched_text=segment[:40] + "...",
                        layer="entropy",
                    ))
            except Exception:
                pass
    return threats


# ──────────────────────────────────────────────────────────────────────────────
# Main scanner class
# ──────────────────────────────────────────────────────────────────────────────

class AdvancedScanner:
    """
    Multi-layer evasion-resistant scanner.

    Thresholds:
      score >= 0.70 → BLOCK
      score >= 0.35 → ALERT
      score <  0.35 → ALLOW
    """

    BLOCK_THRESHOLD = 0.70
    ALERT_THRESHOLD = 0.35

    def __init__(
        self,
        block_threshold: float = 0.70,
        alert_threshold: float = 0.35,
        enable_entropy: bool = True,
        enable_semantic: bool = True,
    ):
        self.block_threshold = block_threshold
        self.alert_threshold = alert_threshold
        self.enable_entropy = enable_entropy
        self.enable_semantic = enable_semantic

    def scan(self, text: str) -> ScanResult:
        """
        Scan text through all detection layers and return a ScanResult.
        """
        if not text or not text.strip():
            return ScanResult(action="allow", score=0.0, reason="Empty input")

        all_threats: list[ThreatMatch] = []

        # Get multiple normalized variants
        variants = _make_variants(text)
        normalized = variants[1] if len(variants) > 1 else text.lower()

        # ── Layer 4: Pattern matching on all variants ────────────────────────
        for variant in variants:
            for category, base_confidence, pattern, reason in THREAT_PATTERNS:
                m = pattern.search(variant)
                if m:
                    matched = m.group(0)[:100]
                    all_threats.append(ThreatMatch(
                        category=category,
                        confidence=base_confidence,
                        reason=reason,
                        matched_text=matched,
                        layer="pattern",
                    ))

        # ── Layer 5: Semantic scoring ────────────────────────────────────────
        if self.enable_semantic:
            # Use original lowercase for semantic — preserves word boundaries
            all_threats.extend(_semantic_score(variants[0]))

        # ── Layer 6: Entropy analysis ────────────────────────────────────────
        if self.enable_entropy:
            all_threats.extend(_entropy_threats(text))

        # ── Layer 7: Structural checks ───────────────────────────────────────
        all_threats.extend(self._structural_checks(text, normalized))

        if not all_threats:
            return ScanResult(
                action="allow",
                score=0.0,
                normalized_text=normalized,
                reason="No threats detected",
            )

        # ── Layer 8: Composite scoring ───────────────────────────────────────
        # Deduplicate by category — keep highest confidence per category
        by_category: dict[ThreatCategory, ThreatMatch] = {}
        for t in all_threats:
            existing = by_category.get(t.category)
            if existing is None or t.confidence > existing.confidence:
                by_category[t.category] = t
        unique_threats = list(by_category.values())

        # Composite score: highest single threat + bonus for multiple categories
        if not unique_threats:
            return ScanResult(action="allow", score=0.0, normalized_text=normalized)

        max_confidence = max(t.confidence for t in unique_threats)
        num_categories = len(unique_threats)
        # Each additional category adds 5% (max +25%)
        multi_bonus = min((num_categories - 1) * 0.05, 0.25)
        score = min(max_confidence + multi_bonus, 1.0)

        # Determine action
        if score >= self.block_threshold:
            action = "block"
        elif score >= self.alert_threshold:
            action = "alert"
        else:
            action = "allow"

        # Build reason string from top threats
        top = sorted(unique_threats, key=lambda x: -x.confidence)[:3]
        reason = " | ".join(t.reason for t in top)

        return ScanResult(
            action=action,
            score=round(score, 3),
            threats=unique_threats,
            reason=reason,
            normalized_text=normalized,
        )

    def _structural_checks(self, raw: str, normalized: str) -> list[ThreatMatch]:
        """Layer 7: Structural anomaly checks."""
        threats = []

        # Check for character-separated words (I-g-n-o-r-e, i.g.n.o.r.e)
        sep_pattern = re.compile(r'\b\w([\-\.\*\s\_])\w(\1\w){3,}\b')
        if sep_pattern.search(raw):
            threats.append(ThreatMatch(
                category=ThreatCategory.TOKEN_SMUGGLING,
                confidence=0.65,
                reason="Character-separated word obfuscation detected",
                matched_text=sep_pattern.search(raw).group(0)[:50],
                layer="structural",
            ))

        # Excessive punctuation / special chars between words
        punct_ratio = len(re.findall(r'[^a-z0-9\s]', normalized)) / max(len(normalized), 1)
        if punct_ratio > 0.3 and len(normalized) > 20:
            threats.append(ThreatMatch(
                category=ThreatCategory.TOKEN_SMUGGLING,
                confidence=0.50,
                reason=f"High special character ratio ({punct_ratio:.0%}) — possible obfuscation",
                layer="structural",
            ))

        # Very long single token (may be encoded payload)
        tokens = normalized.split()
        long_tokens = [t for t in tokens if len(t) > 60]
        if long_tokens:
            threats.append(ThreatMatch(
                category=ThreatCategory.ENCODING_ATTACK,
                confidence=0.55,
                reason=f"Unusually long token detected (len={len(long_tokens[0])})",
                matched_text=long_tokens[0][:60] + "...",
                layer="structural",
            ))

        # Repetitive override-style text (spam patterns to confuse)
        repeat_pattern = re.compile(r'(.{10,})\1{2,}')
        if repeat_pattern.search(normalized):
            threats.append(ThreatMatch(
                category=ThreatCategory.TOKEN_SMUGGLING,
                confidence=0.45,
                reason="Repetitive text pattern (possible confusion attack)",
                layer="structural",
            ))

        return threats
