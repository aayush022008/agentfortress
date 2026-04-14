use crate::models::{PolicyAction, PolicyActionKind};
use regex::Regex;
use std::sync::OnceLock;

// ── Normalization ─────────────────────────────────────────────────────────────

fn normalize(text: &str) -> String {
    let mut result = String::with_capacity(text.len());

    for c in text.chars() {
        // Remove zero-width chars
        if matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{00AD}' | '\u{FEFF}') {
            continue;
        }
        // Full-width Latin Ａ-Ｚ → A-Z, ａ-ｚ → a-z
        if c >= '\u{FF21}' && c <= '\u{FF3A}' {
            result.push(char::from_u32(c as u32 - 0xFF21 + b'A' as u32).unwrap_or(c));
            continue;
        }
        if c >= '\u{FF41}' && c <= '\u{FF5A}' {
            result.push(char::from_u32(c as u32 - 0xFF41 + b'a' as u32).unwrap_or(c));
            continue;
        }
        // Homoglyphs
        let mapped = match c {
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x',
            'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H',
            'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T', 'Х' => 'X',
            'у' => 'u', 'У' => 'U',
            'α' => 'a', 'β' => 'b', 'ε' => 'e', 'ι' => 'i', 'ο' => 'o', 'ρ' => 'p',
            'τ' => 't', 'υ' => 'u', 'ν' => 'v', 'ω' => 'w',
            _ => c,
        };
        result.push(mapped);
    }

    // Lowercase
    let result = result.to_lowercase();

    // Leet decode
    let result: String = result.chars().map(|c| match c {
        '0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's',
        '6' => 'g', '7' => 't', '8' => 'b', '@' => 'a', '$' => 's', '!' => 'i',
        _ => c,
    }).collect();

    // Strip char-separators between letters (only [-._*], NOT spaces)
    static SEP_RE: OnceLock<Regex> = OnceLock::new();
    let sep_re = SEP_RE.get_or_init(|| Regex::new(r"(?P<a>[a-z])[-._*](?P<b>[a-z])").unwrap());
    let mut result = result;
    while sep_re.is_match(&result) {
        result = sep_re.replace_all(&result, "${a}${b}").into_owned();
    }

    // Collapse whitespace
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── Pattern definitions ───────────────────────────────────────────────────────

struct ScanPattern {
    name: &'static str,
    confidence: f64,
    re: &'static str,
}

const INPUT_PATTERNS: &[ScanPattern] = &[
    ScanPattern { name: "instruction_override", confidence: 0.95,
        re: r"(?i)\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|constraints?|guidelines?)" },
    ScanPattern { name: "instruction_override", confidence: 0.95,
        re: r"(?i)\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)" },
    ScanPattern { name: "soft_bypass", confidence: 0.80,
        re: r"(?i)\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b" },
    ScanPattern { name: "jailbreak", confidence: 0.98,
        re: r"(?i)\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?)" },
    ScanPattern { name: "jailbreak", confidence: 0.88,
        re: r"(?i)\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b" },
    ScanPattern { name: "jailbreak", confidence: 0.92,
        re: r"(?i)\b(for\s+(a\s+)?(novel|story|game|book|fiction|roleplay)|my\s+(grandmother|grandma))\b.{0,100}\b(synthesize|manufacture|make|create)\b.{0,60}\b(drug|weapon|explosive|malware|bomb)" },
    ScanPattern { name: "role_manip", confidence: 0.88,
        re: r"(?i)\byou\s+(are\s+now|have\s+become)\b.{0,60}\b(different|new|another)\b.{0,30}\b(ai|model|assistant)" },
    ScanPattern { name: "token_smuggling", confidence: 0.92,
        re: r"(?i)(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\|user\|>|<\|assistant\|>)" },
    ScanPattern { name: "scope_creep", confidence: 0.95,
        re: r"(?i)rm\s+-rf|drop\s+table|truncate\s+table" },
    ScanPattern { name: "scope_creep", confidence: 0.90,
        re: r"(?i)(access|read|open|list).{0,40}(/etc/passwd|\.ssh/|\.aws/|\.env|id_rsa|credentials?)" },
    ScanPattern { name: "data_exfil", confidence: 0.90,
        re: r"(?i)(exfiltrate|exfil|send\s+to\s+https?|POST\s+to|upload\s+to\s+https?)" },
    ScanPattern { name: "prompt_leak", confidence: 0.88,
        re: r"(?i)(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are)).{0,40}(your\s+(system\s+prompt|instructions?|prompt|context))" },
    ScanPattern { name: "indirect_inject", confidence: 0.88,
        re: r#"(?i)"(instruction|system_prompt|prompt|role)"\s*:\s*"[^"]{0,200}(ignore|disregard|bypass|override|forget)[^"]{0,200}""# },
    ScanPattern { name: "classic", confidence: 0.90,
        re: r"(?i)\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b" },
    ScanPattern { name: "reverse_psychology", confidence: 0.85,
        re: r"(?i)\bwhatever\s+you\s+do\b.{0,30}\b(don.t|do\s+not)\b.{0,30}\b(follow|obey)\b.{0,30}\b(instructions?|rules?)" },
    ScanPattern { name: "real_instructions", confidence: 0.88,
        re: r"(?i)\b(your\s+(real|actual|true)\s+instructions?\s+(are|follow)|actual\s+instructions?\s+are)" },
    ScanPattern { name: "role_prefix_injection", confidence: 0.88,
        re: r"(?im)^\s*(SYSTEM\s*:\s*|USER\s*:\s*|ASSISTANT\s*:\s*)" },
    ScanPattern { name: "rtl_override", confidence: 0.85,
        re: r"[\u{202E}\u{202D}\u{202C}\u{202B}\u{202A}\u{200F}\u{200E}]" },
    ScanPattern { name: "multilang_injection", confidence: 0.90,
        re: r"(?i)(ignorez\s+toutes\s+les\s+instructions|ignoriere\s+alle\s+(vorherigen\s+)?anweisungen|ignora\s+todas\s+las\s+instrucciones)" },
];

const OUTPUT_PATTERNS: &[ScanPattern] = &[
    ScanPattern { name: "secret_leakage", confidence: 0.95,
        re: r"sk-[a-zA-Z0-9\-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}" },
    ScanPattern { name: "pii_credit_card", confidence: 0.90,
        re: r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b" },
    ScanPattern { name: "pii_ssn", confidence: 0.85,
        re: r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b" },
    ScanPattern { name: "pii_email", confidence: 0.70,
        re: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b" },
    ScanPattern { name: "secret_leakage", confidence: 0.88,
        re: r"(?i)(password|passwd|secret|api_key|access_token|auth_token)\s*[=:]\s*\S{8,}" },
];

fn compile_patterns(patterns: &[ScanPattern]) -> Vec<(f64, &'static str, Regex)> {
    patterns.iter().map(|p| (p.confidence, p.name, Regex::new(p.re).expect("bad pattern"))).collect()
}

// ── Scanner struct ─────────────────────────────────────────────────────────────

pub struct Scanner {
    block_threshold: f64,
    alert_threshold: f64,
    input_re: Vec<(f64, &'static str, Regex)>,
    output_re: Vec<(f64, &'static str, Regex)>,
}

impl Scanner {
    pub fn new() -> Self {
        Self::with_thresholds(0.70, 0.35)
    }

    pub fn with_thresholds(block_threshold: f64, alert_threshold: f64) -> Self {
        Self {
            block_threshold,
            alert_threshold,
            input_re: compile_patterns(INPUT_PATTERNS),
            output_re: compile_patterns(OUTPUT_PATTERNS),
        }
    }

    pub fn scan(&self, text: &str) -> PolicyAction {
        let normalized = normalize(text);
        let lower = text.to_lowercase();
        let variants = [lower.as_str(), normalized.as_str()];

        let mut max_conf = 0.0_f64;
        let mut best_reason = String::new();

        for variant in &variants {
            for (conf, name, re) in &self.input_re {
                if re.is_match(variant) && *conf > max_conf {
                    max_conf = *conf;
                    best_reason = name.to_string();
                }
            }
        }

        let action = if max_conf >= self.block_threshold {
            PolicyActionKind::Block
        } else if max_conf >= self.alert_threshold {
            PolicyActionKind::Alert
        } else {
            PolicyActionKind::Allow
        };

        PolicyAction {
            action,
            reason: if best_reason.is_empty() { None } else { Some(best_reason) },
            score: max_conf,
        }
    }

    pub fn scan_output(&self, text: &str) -> PolicyAction {
        let mut max_conf = 0.0_f64;
        let mut best_reason = String::new();

        for (conf, name, re) in &self.output_re {
            if re.is_match(text) && *conf > max_conf {
                max_conf = *conf;
                best_reason = name.to_string();
            }
        }

        let action = if max_conf >= self.block_threshold {
            PolicyActionKind::Block
        } else if max_conf >= self.alert_threshold {
            PolicyActionKind::Alert
        } else {
            PolicyActionKind::Allow
        };

        PolicyAction {
            action,
            reason: if best_reason.is_empty() { None } else { Some(best_reason) },
            score: max_conf,
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// Unified scan by direction: "input" | "output"
    pub fn scan_with_direction(&self, text: &str, is_output: bool) -> crate::models::PolicyAction {
        if is_output { self.scan_output(text) } else { self.scan(text) }
    }
}
