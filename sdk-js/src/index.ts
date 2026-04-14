/**
 * AgentFortress — Runtime protection for AI agents
 * Advanced multi-layer scanner with evasion resistance
 * @packageDocumentation
 *
 * v2.1.0 — Major upgrade:
 *  • All v2.0.0 features retained
 *  • Perplexity-like structural scoring
 *  • Trust segmentation (scanSegmented)
 *  • Canary token system
 *  • Redaction engine
 *  • Shadow mode (never blocks, only observes)
 *  • Custom policy rules engine
 *  • Tool call monitor
 *  • Context window poisoning detector
 *  • Threat fingerprinting
 *  • Structured scan report (scanDetailed)
 *  • MITRE ATLAS technique mapping
 *  • Session risk profile
 */

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentFortressConfig {
  apiKey?: string;
  serverUrl?: string;
  mode?: 'local' | 'remote';
  logLevel?: 'debug' | 'info' | 'warn' | 'error' | 'silent';
  blockThreshold?: number;
  alertThreshold?: number;
  /** If true, protect() will throw on blocked input instead of returning null */
  throwOnBlock?: boolean;
  /** Max suspicious calls per sessionWindow before auto-block (default: 5) */
  velocityLimit?: number;
  /** Velocity window in milliseconds (default: 60_000) */
  velocityWindowMs?: number;
  /** Enable output scanning for PII / secret leakage (default: true) */
  scanOutputs?: boolean;
  /** Custom block message returned to caller when input is blocked */
  blockMessage?: string;
  /**
   * Shadow mode: scan everything but NEVER block. Returns 'shadow_allow' instead of block/alert.
   * Perfect for production tuning without risk.
   */
  shadowMode?: boolean;
}

export interface ThreatEvent {
  id: string;
  timestamp: number;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  agentId?: string;
  sessionId?: string;
  payload?: Record<string, unknown>;
}

export interface PolicyAction {
  action: 'allow' | 'block' | 'alert' | 'shadow_allow';
  reason?: string;
  score?: number;
  threats?: Array<{ category: string; confidence: number; reason: string }>;
  /** Fingerprint of the threat pattern (stable hash) */
  fingerprint?: string;
  /** MITRE ATLAS technique ID */
  mitreTechnique?: string;
  /** True if this is a shadow mode decision */
  isShadow?: boolean;
  /** True if this fingerprint was seen for the first time in this session */
  isNovel?: boolean;
  /** How many times this exact fingerprint was seen before */
  similarAttackCount?: number;
}

export interface AuditRecord {
  timestamp: number;
  sessionId: string;
  agentId?: string;
  direction: 'input' | 'output';
  text: string;
  decision: PolicyAction;
  /** True if this is a shadow mode record */
  isShadow?: boolean;
  /** Fingerprint of the threat pattern */
  fingerprint?: string;
  /** MITRE ATLAS technique */
  mitreTechnique?: string;
}

export type ThreatHandler = (event: ThreatEvent) => void;
export type AuditHandler = (record: AuditRecord) => void;

// ─── NEW TYPES ────────────────────────────────────────────────────────────────

export interface RedactionFinding {
  type: 'api_key' | 'credit_card' | 'ssn' | 'email' | 'secret_token';
  original: string;
  replacement: string;
  index: number;
}

export interface RedactionResult {
  redacted: string;
  findings: RedactionFinding[];
}

export interface SegmentInput {
  text: string;
  trust: 'trusted' | 'untrusted' | 'external';
}

export interface SegmentResult {
  segment: SegmentInput;
  decision: PolicyAction;
  skipped?: boolean;
}

export interface SegmentedScanResult {
  segments: SegmentResult[];
  overall: PolicyAction;
}

export interface CustomRule {
  id: string;
  condition: (result: PolicyAction) => boolean;
  action: 'allow' | 'block' | 'alert';
  reason: string;
}

export interface ToolPolicy {
  allowList?: string[];
  denyList?: string[];
  maxCallsPerTurn?: number;
  requireApproval?: string[];
}

export interface ToolCallDecision {
  action: 'allow' | 'block' | 'alert' | 'require_approval';
  reason: string;
}

export interface ContextChunk {
  source: string;
  content: string;
}

export interface ContextScanInput {
  systemPrompt?: string;
  retrievedChunks?: ContextChunk[];
  userMessage?: string;
}

export interface PoisonedChunkResult extends ContextChunk {
  decision: PolicyAction;
}

export interface ContextScanResult {
  clean: boolean;
  poisonedChunks: PoisonedChunkResult[];
  decision: 'allow' | 'block' | 'alert';
}

export interface NormalizationLayer {
  applied: string[];
  normalized: string;
}

export interface DetailedScanLayers {
  normalization: NormalizationLayer;
  patterns: Array<{ category: string; confidence: number; reason: string }>;
  semantic: Array<{ category: string; confidence: number }>;
  structural: { charSepDetected: boolean; highEntropyTokens: number; structuralScore: number };
  sessionContext: { boost: number; priorThreats: number };
  velocity: { count: number; limit: number; triggered: boolean };
  customRules: Array<{ ruleId: string; applied: boolean; action?: string }>;
}

export interface DetailedScanReport extends PolicyAction {
  fingerprint: string;
  isNovel: boolean;
  layers: DetailedScanLayers;
  recommendation: string;
  mitreTechnique: string;
}

export interface SessionRiskProfile {
  sessionId: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  totalScans: number;
  blockedCount: number;
  alertCount: number;
  topThreatCategories: string[];
  firstSeen: number;
  lastSeen: number;
  riskScore: number;
  recommendation: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// MITRE ATLAS mapping
// ─────────────────────────────────────────────────────────────────────────────

const MITRE_ATLAS: Record<string, string> = {
  instruction_override: 'AML.T0051.000',
  jailbreak: 'AML.T0054.000',
  data_exfil: 'AML.T0025',
  role_manipulation: 'AML.T0051.001',
  scope_creep: 'AML.T0043',
  token_smuggling: 'AML.T0049',
  prompt_leak: 'AML.T0056.000',
  indirect_injection: 'AML.T0051.000',
  pii_ssn: 'AML.T0025',
  pii_credit_card: 'AML.T0025',
  pii_email: 'AML.T0025',
  secret_leakage: 'AML.T0056.000',
};

function getMitreForThreats(threats: Array<{ category: string; confidence: number; reason: string }>): string {
  if (!threats || threats.length === 0) return '';
  const sorted = [...threats].sort((a, b) => b.confidence - a.confidence);
  return MITRE_ATLAS[sorted[0].category] ?? '';
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalisation helpers
// ─────────────────────────────────────────────────────────────────────────────

const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic look-alikes
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
  'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  // Greek look-alikes
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
  // Full-width Latin
  'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F',
  'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L',
  'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
  'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X',
  'Ｙ': 'Y', 'Ｚ': 'Z',
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f',
  'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l',
  'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
  'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x',
  'ｙ': 'y', 'ｚ': 'z',
};

const LEET: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
};

function normalize(text: string): { result: string; applied: string[] } {
  const applied: string[] = [];
  // Replace homoglyphs
  let result = text.split('').map(c => HOMOGLYPHS[c] ?? c).join('');
  if (result !== text) applied.push('homoglyph');
  // Remove zero-width / invisible chars
  result = result.replace(/[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u034f\u2028\u2029]/g, '');
  // Leet-speak decode
  const beforeLeet = result;
  result = result.toLowerCase().split('').map(c => LEET[c] ?? c).join('');
  if (result !== beforeLeet.toLowerCase()) applied.push('leet');
  // Remove separators between letters (I-g-n-o-r-e → ignore) — but NOT spaces (would break word boundary matching)
  const beforeSep = result;
  result = result.replace(/(?<=[a-z])[-._*](?=[a-z])/g, '');
  if (result !== beforeSep) applied.push('char_sep');
  // Collapse whitespace
  result = result.replace(/\s+/g, ' ').trim();
  return { result, applied };
}

function normalizeStr(text: string): string {
  return normalize(text).result;
}

function makeVariants(text: string): string[] {
  const lower = text.toLowerCase();
  const norm = normalizeStr(text);
  const noPunct = norm.replace(/[^a-z0-9 ]/g, '');
  const noSpace = norm.replace(/\s+/g, '');
  const alphaOnly = norm.replace(/[^a-z]/g, '');
  return [...new Set([lower, norm, noPunct, noSpace, alphaOnly])];
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy helper (Shannon entropy)
// ─────────────────────────────────────────────────────────────────────────────

function shannonEntropy(text: string): number {
  const freq: Record<string, number> = {};
  for (const ch of text) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = text.length;
  return Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc - p * Math.log2(p);
  }, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple stable hash (for fingerprinting)
// ─────────────────────────────────────────────────────────────────────────────

function simpleHash(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

function computeFingerprint(threats: Array<{ category: string; confidence: number; reason: string }>): string {
  if (!threats || threats.length === 0) return '';
  const sorted = [...threats].sort((a, b) => a.category.localeCompare(b.category));
  const key = sorted.map(t => `${t.category}:${Math.round(t.confidence * 100)}`).join('|');
  return simpleHash(key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural / perplexity-like scoring
// ─────────────────────────────────────────────────────────────────────────────

const IMPERATIVE_INJECTION_VERBS = /^(ignore|disregard|forget|override|pretend|act\s+as|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b/i;
const TOPIC_SHIFT_MARKERS = /\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,30}(ignore|forget|disregard|bypass|override|pretend|act\s+as)/i;
const QUOTE_THEN_INSTRUCTION = /[""][^""]{5,}[""]\s*[.,]?\s*(ignore|forget|disregard|bypass|override)/i;
const INSTRUCTION_KEYWORDS_RE = /\b(ignore|disregard|forget|override|bypass|pretend|act\s+as|jailbreak|unlock|uncensor|unrestricted)\b/gi;

function structuralScore(text: string): number {
  let score = 0;
  const trimmed = text.trim();

  // 1. Starts with imperative injection verb
  if (IMPERATIVE_INJECTION_VERBS.test(trimmed)) {
    score += 0.25;
  }

  // 2. Sudden topic shift followed by injection
  if (TOPIC_SHIFT_MARKERS.test(trimmed)) {
    score += 0.20;
  }

  // 3. Unusual punctuation density
  const punctCount = (trimmed.match(/[!?;:,\-_*[\]{}\\|]/g) ?? []).length;
  const density = punctCount / Math.max(trimmed.length, 1);
  if (density > 0.08) score += 0.10;
  if (density > 0.15) score += 0.10;

  // 4. Quoted speech followed by instructions
  if (QUOTE_THEN_INSTRUCTION.test(trimmed)) {
    score += 0.20;
  }

  // 5. Multiple sentence fragments each containing injection keywords
  const sentences = trimmed.split(/[.!?]+/).filter(s => s.trim().length > 3);
  const kwMatches = sentences.filter(s => INSTRUCTION_KEYWORDS_RE.test(s));
  INSTRUCTION_KEYWORDS_RE.lastIndex = 0;
  if (kwMatches.length >= 2) {
    score += 0.15 * Math.min(kwMatches.length, 3);
  }

  return Math.min(score, 0.60);
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern library (input threats)
// ─────────────────────────────────────────────────────────────────────────────

interface PatternDef {
  pattern: RegExp;
  category: string;
  confidence: number;
  reason: string;
}

const INPUT_PATTERNS: PatternDef[] = [
  // ── Instruction Override ──────────────────────────────────────────────────
  { pattern: /\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|context|constraints?|guidelines?)/i, category: 'instruction_override', confidence: 0.95, reason: 'Ignore instructions pattern' },
  { pattern: /\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)/i, category: 'instruction_override', confidence: 0.95, reason: 'Disregard/override instructions' },
  { pattern: /\b(pretend|act|behave|imagine|suppose|assume)\b.{0,30}\b(you\s*(are|were|have\s*no)|without|free\s*from)\b.{0,50}\b(rules?|restrictions?|limits?|filters?|guidelines?|safety|ethics?)/i, category: 'instruction_override', confidence: 0.90, reason: 'Pretend without restrictions' },
  { pattern: /\b(new|updated?|actual|real|true|correct|only)\b.{0,20}\binstructions?\b.{0,10}(are|is|follow|:\s)/i, category: 'instruction_override', confidence: 0.88, reason: 'New instructions injection' },
  { pattern: /\b(stop\s+being|stop\s+following|no\s+longer\s+follow|don.t\s+follow)\b.{0,40}\b(your|the)\b.{0,20}\b(instructions?|rules?|guidelines?|training)/i, category: 'instruction_override', confidence: 0.85, reason: 'Stop following instructions' },
  { pattern: /\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b/i, category: 'instruction_override', confidence: 0.80, reason: 'Soft bypass: btw/also/anyway + override verb' },
  { pattern: /\b(whatever\s+you\s+do|don.t)\b.{0,30}\b(follow|obey|listen\s+to|comply)\b.{0,30}\b(instructions?|rules?|guidelines?)/i, category: 'instruction_override', confidence: 0.80, reason: 'Reverse psychology override' },

  // ── Jailbreak ─────────────────────────────────────────────────────────────
  { pattern: /\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?|no\s+restrictions?)/i, category: 'jailbreak', confidence: 0.98, reason: 'DAN jailbreak' },
  { pattern: /\bjailbreak(ed)?\b/i, category: 'jailbreak', confidence: 0.90, reason: 'Explicit jailbreak mention' },
  { pattern: /\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b/i, category: 'jailbreak', confidence: 0.88, reason: 'Fictional mode activation' },
  { pattern: /\b(opposite|reverse|evil|chaos|dark|shadow|unethical)\s+(mode|version|persona|self|ai)\b/i, category: 'jailbreak', confidence: 0.85, reason: 'Evil/opposite mode' },
  { pattern: /\b(no\s+(restrictions?|limits?|filters?|censorship|guidelines?|ethics?|safety)|unrestricted(ly)?|unfiltered|uncensored)\b.{0,60}\b(respond|answer|reply|say|tell|generate|produce|output|write)\b/i, category: 'jailbreak', confidence: 0.85, reason: 'Unrestricted response request' },
  { pattern: /\bas\s+an?\s+(ai\s+without\s+(restrictions?|limits?)|unrestricted\s+ai|unfiltered\s+(ai|model|assistant))/i, category: 'jailbreak', confidence: 0.88, reason: 'As an unrestricted AI' },
  { pattern: /\b(my\s+grandma\s+used\s+to|bedtime\s+story|read\s+me\s+a\s+story|hypothetically\s+speaking|for\s+a\s+(novel|book|story|game|fiction))\b.{0,200}\b(synthesize|manufacture|make|create|build|produce)\b.{0,60}\b(drug|weapon|explosive|malware|virus|ransomware|bomb)/i, category: 'jailbreak', confidence: 0.92, reason: 'Story-wrapper jailbreak for dangerous content' },

  // ── Role Manipulation ─────────────────────────────────────────────────────
  { pattern: /\b(act|behave|respond|speak)\b.{0,20}\bas\b.{0,30}\b(a\s+hacker|an?\s+attacker|a\s+criminal|a\s+pirate|a\s+villain|an?\s+evil|a\s+terrorist|a\s+malicious)/i, category: 'role_manipulation', confidence: 0.88, reason: 'Act as malicious persona' },
  { pattern: /\bpretend\b.{0,30}\b(to\s+be|you.re|you\s+are)\b.{0,50}\b(hacker|cracker|attacker|criminal|pirate|villain|evil|malicious)/i, category: 'role_manipulation', confidence: 0.85, reason: 'Pretend to be malicious actor' },
  { pattern: /\byou\s+(are\s+now|have\s+become|will\s+become)\b.{0,60}\b(different|new|another|alternative)\b.{0,30}\b(ai|model|assistant|system|bot)/i, category: 'role_manipulation', confidence: 0.88, reason: 'You are now different AI' },
  { pattern: /\bswitch\s+(to|into)\b.{0,30}\b(a\s+new|another|different)\b.{0,30}\b(persona|role|mode|character|personality)/i, category: 'role_manipulation', confidence: 0.82, reason: 'Switch to new persona' },

  // ── Token Smuggling ───────────────────────────────────────────────────────
  { pattern: /(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\/system>|<\|endoftext\|>|###\s*Human:|###\s*Assistant:|<\|user\|>|<\|assistant\|>)/i, category: 'token_smuggling', confidence: 0.92, reason: 'LLM special token injection' },
  { pattern: /\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}/i, category: 'token_smuggling', confidence: 0.82, reason: 'Unicode/HTML/URL escape sequences' },
  { pattern: /\b(aWdub3Jl|aWdub3Jl|ZGlzcmVnYXJk|b3ZlcnJpZGU=|Zm9yZ2V0|amFpbGJyZWFr)/i, category: 'token_smuggling', confidence: 0.88, reason: 'Base64-encoded override keywords' },

  // ── Scope Creep / System Commands ─────────────────────────────────────────
  { pattern: /\b(rm\s+-rf|del\s+\/f|format\s+c:|drop\s+table|truncate\s+table|drop\s+database)\b/i, category: 'scope_creep', confidence: 0.95, reason: 'Destructive command' },
  { pattern: /\b(access|read|open|list|cat|type)\b.{0,40}\b(\/etc\/passwd|\/etc\/shadow|\.ssh\/|\.aws\/|\.env|id_rsa|credentials?|secrets?\b)/i, category: 'scope_creep', confidence: 0.90, reason: 'Sensitive file access attempt' },
  { pattern: /\b(curl|wget|nc|ncat|netcat|bash\s*-i|python\s*-c|exec\(|eval\(|os\.system|subprocess)/i, category: 'scope_creep', confidence: 0.85, reason: 'Shell/code execution attempt' },
  { pattern: /\b(exfiltrate|exfil|send\s+to\s+http|POST\s+to|upload\s+to\s+http|webhook\.site|requestbin)/i, category: 'data_exfil', confidence: 0.90, reason: 'Data exfiltration pattern' },

  // ── Indirect / Nested Injection ───────────────────────────────────────────
  { pattern: /["']?\s*(instruction|system_prompt|prompt|role)\s*["']?\s*:\s*["'].{0,200}(ignore|override|bypass|jailbreak)/i, category: 'indirect_injection', confidence: 0.88, reason: 'Injection hidden in JSON field' },
  { pattern: /```[\s\S]{0,20}(ignore|override|bypass|jailbreak|disregard)[\s\S]{0,200}(instructions?|rules?|guidelines?)/i, category: 'indirect_injection', confidence: 0.85, reason: 'Injection hidden in code block' },
  { pattern: /https?:\/\/[^\s]*[?&](prompt|instruction|system|query)=[^\s]*?(ignore|override|bypass|inject)/i, category: 'indirect_injection', confidence: 0.88, reason: 'Injection via URL parameter' },

  // ── Prompt Leaking ─────────────────────────────────────────────────────────
  { pattern: /\b(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are))\b.{0,40}\b(your\s+(system\s+prompt|instructions?|prompt|context)|the\s+(system\s+prompt|initial\s+prompt))/i, category: 'prompt_leak', confidence: 0.88, reason: 'Attempt to extract system prompt' },
  { pattern: /\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b/i, category: 'instruction_override', confidence: 0.90, reason: 'Classic ignore-above injection' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Output patterns (sensitive data leakage detection)
// ─────────────────────────────────────────────────────────────────────────────

const OUTPUT_PATTERNS: PatternDef[] = [
  { pattern: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/, category: 'pii_ssn', confidence: 0.85, reason: 'Possible SSN in output' },
  { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b/, category: 'pii_credit_card', confidence: 0.90, reason: 'Possible credit card number in output' },
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b/, category: 'pii_email', confidence: 0.70, reason: 'Email address in output' },
  { pattern: /\b(sk-[a-zA-Z0-9-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|ghs_[a-zA-Z0-9]{20,}|xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})\b/, category: 'secret_leakage', confidence: 0.95, reason: 'API key/secret token in output' },
  { pattern: /\b(password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["']?[^\s"']{8,}/i, category: 'secret_leakage', confidence: 0.88, reason: 'Credential assignment in output' },
  { pattern: /\b(my\s+system\s+prompt\s+(is|reads|says)|you\s+are\s+an?\s+ai\s+assistant\s+.{0,100}your\s+instructions)/i, category: 'prompt_leak', confidence: 0.85, reason: 'System prompt content leaked in output' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Semantic keyword groups
// ─────────────────────────────────────────────────────────────────────────────

const SEMANTIC_GROUPS: Array<{ keywords: string[]; weight: number; category: string; reason: string }> = [
  { keywords: ['ignore', 'disregard', 'forget', 'override', 'bypass', 'dismiss', 'cancel', 'nullify', 'void', 'erase', 'clear', 'reset', 'undo', 'revoke', 'annul', 'negate', 'supersede', 'overwrite', 'negate', 'suppress'], weight: 0.30, category: 'instruction_override', reason: 'Override verb' },
  { keywords: ['instructions', 'rules', 'guidelines', 'constraints', 'directives', 'prompt', 'training', 'restrictions', 'limitations', 'boundaries', 'policies', 'principles', 'constitution', 'alignment'], weight: 0.20, category: 'instruction_override', reason: 'Instructions noun' },
  { keywords: ['unrestricted', 'unfiltered', 'uncensored', 'unlimited', 'unbound', 'unchained', 'no limits', 'no rules', 'no restrictions', 'no filter', 'no safety', 'without guardrails', 'no guardrails'], weight: 0.40, category: 'jailbreak', reason: 'Unrestricted keyword' },
  { keywords: ['pretend', 'roleplay', 'imagine you are', 'act as if', 'simulate', 'you are now', 'become', 'transform into', 'embody', 'take on the role', 'play the character', 'in this scenario you are'], weight: 0.25, category: 'role_manipulation', reason: 'Role manipulation keyword' },
  { keywords: ['hacker', 'attacker', 'criminal', 'pirate', 'villain', 'evil', 'malicious', 'adversary', 'black hat', 'cracker', 'threat actor', 'bad actor'], weight: 0.35, category: 'role_manipulation', reason: 'Malicious persona keyword' },
  { keywords: ['exfiltrate', 'exfil', 'steal', 'leak', 'smuggle', 'siphon', 'harvest', 'dump secrets', 'extract credentials', 'send data to'], weight: 0.45, category: 'data_exfil', reason: 'Exfiltration keyword' },
];

function semanticScore(text: string): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  const lower = text.toLowerCase();
  for (const group of SEMANTIC_GROUPS) {
    const found = group.keywords.filter(kw => lower.includes(kw));
    if (found.length >= 2) {
      threats.push({ category: group.category, confidence: Math.min(group.weight * 1.5 * found.length, 0.85), reason: `${group.reason}: [${found.slice(0, 3).join(', ')}]` });
    } else if (found.length === 1) {
      threats.push({ category: group.category, confidence: group.weight * 0.6, reason: `${group.reason}: [${found[0]}]` });
    }
  }
  return threats;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy-based obfuscation detection
// ─────────────────────────────────────────────────────────────────────────────

function detectHighEntropyObfuscation(text: string): { threats: Array<{ category: string; confidence: number; reason: string }>; highEntropyCount: number } {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  const tokens = text.split(/\s+/).filter(t => t.length >= 16);
  let highEntropyCount = 0;
  for (const token of tokens) {
    const e = shannonEntropy(token);
    if (e > 4.8 && token.length >= 20) {
      highEntropyCount++;
      threats.push({ category: 'token_smuggling', confidence: 0.70, reason: `High-entropy token (possible encoded payload, entropy=${e.toFixed(2)})` });
    }
  }
  return { threats, highEntropyCount };
}

// ─────────────────────────────────────────────────────────────────────────────
// Nested/contextual injection detector
// ─────────────────────────────────────────────────────────────────────────────

function detectNestedInjection(text: string): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  const b64Matches = text.match(/[A-Za-z0-9+/]{24,}={0,2}/g) ?? [];
  for (const blob of b64Matches.slice(0, 5)) {
    try {
      const decoded = Buffer.from(blob, 'base64').toString('utf8');
      if (/[a-z]{4,}/.test(decoded)) {
        const norm = normalizeStr(decoded);
        for (const def of INPUT_PATTERNS) {
          if (def.pattern.test(norm)) {
            threats.push({ category: 'indirect_injection', confidence: Math.min(def.confidence * 0.9, 0.92), reason: `Encoded payload: ${def.reason}` });
            break;
          }
        }
      }
    } catch { /* ignore */ }
  }
  return threats;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core scan engine
// ─────────────────────────────────────────────────────────────────────────────

function runPatterns(text: string, patterns: PatternDef[], preserveCase = false): Array<{ category: string; confidence: number; reason: string }> {
  const threats: Array<{ category: string; confidence: number; reason: string }> = [];
  const variants = preserveCase ? [text] : makeVariants(text);
  for (const variant of variants) {
    for (const def of patterns) {
      if (def.pattern.test(variant)) {
        threats.push({ category: def.category, confidence: def.confidence, reason: def.reason });
      }
    }
  }
  return threats;
}

function computeAction(
  allThreats: Array<{ category: string; confidence: number; reason: string }>,
  blockThreshold = 0.70,
  alertThreshold = 0.35,
): PolicyAction {
  if (allThreats.length === 0) return { action: 'allow', score: 0, reason: 'Clean' };

  const byCat = new Map<string, { category: string; confidence: number; reason: string }>();
  for (const t of allThreats) {
    const existing = byCat.get(t.category);
    if (!existing || t.confidence > existing.confidence) byCat.set(t.category, t);
  }
  const unique = [...byCat.values()];

  const maxConf = Math.max(...unique.map(t => t.confidence));
  const multiBonus = Math.min((unique.length - 1) * 0.05, 0.25);
  const score = Math.min(maxConf + multiBonus, 1.0);

  const action = score >= blockThreshold ? 'block' : score >= alertThreshold ? 'alert' : 'allow';
  const topThreats = unique.sort((a, b) => b.confidence - a.confidence);
  const reason = topThreats.slice(0, 3).map(t => t.reason).join(' | ');

  return { action, score: Math.round(score * 1000) / 1000, reason, threats: unique };
}

interface AdvancedScanInternals {
  result: PolicyAction;
  normalizationApplied: string[];
  normalized: string;
  patternThreats: Array<{ category: string; confidence: number; reason: string }>;
  semanticThreats: Array<{ category: string; confidence: number; reason: string }>;
  highEntropyCount: number;
  charSepDetected: boolean;
  structuralScoreVal: number;
}

function advancedScanInternal(text: string, blockThreshold = 0.70, alertThreshold = 0.35, isOutput = false): AdvancedScanInternals {
  if (!text?.trim()) {
    return {
      result: { action: 'allow', score: 0 },
      normalizationApplied: [],
      normalized: '',
      patternThreats: [],
      semanticThreats: [],
      highEntropyCount: 0,
      charSepDetected: false,
      structuralScoreVal: 0,
    };
  }

  const normResult = normalize(text);
  const patterns = isOutput ? OUTPUT_PATTERNS : INPUT_PATTERNS;
  const allThreats: Array<{ category: string; confidence: number; reason: string }> = [];

  const patternThreats = runPatterns(text, patterns, isOutput);
  allThreats.push(...patternThreats);

  let semanticThreats: Array<{ category: string; confidence: number; reason: string }> = [];
  let highEntropyCount = 0;
  let charSepDetected = false;
  let structuralScoreVal = 0;

  if (!isOutput) {
    semanticThreats = semanticScore(normResult.result);
    allThreats.push(...semanticThreats);

    charSepDetected = /\b\w([-._*\s])\w(\1\w){3,}\b/.test(text);
    if (charSepDetected) {
      allThreats.push({ category: 'token_smuggling', confidence: 0.65, reason: 'Character-separated word obfuscation' });
    }

    const entropyResult = detectHighEntropyObfuscation(text);
    highEntropyCount = entropyResult.highEntropyCount;
    allThreats.push(...entropyResult.threats);

    allThreats.push(...detectNestedInjection(text));

    // Structural scoring
    structuralScoreVal = structuralScore(text);
    if (structuralScoreVal > 0.20) {
      allThreats.push({ category: 'instruction_override', confidence: structuralScoreVal, reason: `Structural anomaly score: ${structuralScoreVal.toFixed(2)}` });
    }
  }

  return {
    result: computeAction(allThreats, blockThreshold, alertThreshold),
    normalizationApplied: normResult.applied,
    normalized: normResult.result,
    patternThreats,
    semanticThreats,
    highEntropyCount,
    charSepDetected,
    structuralScoreVal,
  };
}

function advancedScan(text: string, blockThreshold = 0.70, alertThreshold = 0.35, isOutput = false): PolicyAction {
  return advancedScanInternal(text, blockThreshold, alertThreshold, isOutput).result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Session threat accumulator (multi-turn context tracking)
// ─────────────────────────────────────────────────────────────────────────────

interface SessionState {
  turnThreats: Array<{ timestamp: number; score: number; category: string }>;
  velocityWindow: number[];
  totalScans: number;
  blockedCount: number;
  alertCount: number;
  firstSeen: number;
  lastSeen: number;
  threatCategories: Map<string, number>;
  fingerprints: Map<string, number>;
}

class SessionTracker {
  private sessions = new Map<string, SessionState>();

  get(sessionId: string): SessionState {
    if (!this.sessions.has(sessionId)) {
      const now = Date.now();
      this.sessions.set(sessionId, {
        turnThreats: [],
        velocityWindow: [],
        totalScans: 0,
        blockedCount: 0,
        alertCount: 0,
        firstSeen: now,
        lastSeen: now,
        threatCategories: new Map(),
        fingerprints: new Map(),
      });
    }
    return this.sessions.get(sessionId)!;
  }

  record(sessionId: string, result: PolicyAction, windowMs: number): number {
    const state = this.get(sessionId);
    const now = Date.now();
    state.lastSeen = now;
    state.totalScans++;

    state.velocityWindow = state.velocityWindow.filter(t => now - t < windowMs);

    if (result.action === 'block') state.blockedCount++;
    else if (result.action === 'alert') state.alertCount++;

    if (result.threats) {
      for (const t of result.threats) {
        state.threatCategories.set(t.category, (state.threatCategories.get(t.category) ?? 0) + 1);
      }
    }

    if (result.action !== 'allow' && result.score! > 0) {
      state.velocityWindow.push(now);
      state.turnThreats.push({ timestamp: now, score: result.score!, category: result.threats?.[0]?.category ?? 'unknown' });
    }

    if (state.turnThreats.length > 50) state.turnThreats.splice(0, state.turnThreats.length - 50);

    const recentThreats = state.turnThreats.filter(t => now - t.timestamp < windowMs * 5);
    const accumulated = recentThreats.reduce((sum, t) => sum + t.score * 0.3, 0);
    return Math.min(accumulated, 0.40);
  }

  recordFingerprint(sessionId: string, fp: string): { isNovel: boolean; count: number } {
    if (!fp) return { isNovel: true, count: 0 };
    const state = this.get(sessionId);
    const count = state.fingerprints.get(fp) ?? 0;
    state.fingerprints.set(fp, count + 1);
    return { isNovel: count === 0, count };
  }

  velocityCount(sessionId: string): number {
    return this.get(sessionId).velocityWindow.length;
  }

  getSessionRisk(sessionId: string): SessionRiskProfile {
    const state = this.get(sessionId);
    const totalScans = state.totalScans;
    const blockedCount = state.blockedCount;
    const alertCount = state.alertCount;

    let riskScore = 0;
    if (totalScans > 0) {
      riskScore = Math.min((blockedCount * 0.4 + alertCount * 0.15) / Math.max(totalScans, 1) * 3, 1.0);
    }

    const riskLevel: 'low' | 'medium' | 'high' | 'critical' =
      riskScore >= 0.75 ? 'critical' :
      riskScore >= 0.50 ? 'high' :
      riskScore >= 0.25 ? 'medium' : 'low';

    const topThreatCategories = [...state.threatCategories.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([cat]) => cat);

    const recommendation =
      riskLevel === 'critical' ? 'Immediately terminate this session. High attack frequency detected.' :
      riskLevel === 'high' ? 'Consider terminating this session. Multiple threats detected.' :
      riskLevel === 'medium' ? 'Monitor this session closely. Some suspicious activity detected.' :
      'Session appears normal.';

    return {
      sessionId,
      riskLevel,
      totalScans,
      blockedCount,
      alertCount,
      topThreatCategories,
      firstSeen: state.firstSeen,
      lastSeen: state.lastSeen,
      riskScore: Math.round(riskScore * 1000) / 1000,
      recommendation,
    };
  }

  clear(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main SDK class
// ─────────────────────────────────────────────────────────────────────────────

export class AgentFortress {
  private config: Required<AgentFortressConfig>;
  private threatHandlers: ThreatHandler[] = [];
  private auditHandlers: AuditHandler[] = [];
  private sessionId: string;
  private tracker = new SessionTracker();

  // Advanced features state
  private customRules: CustomRule[] = [];
  private toolPolicy: ToolPolicy | null = null;
  private toolCallCount = 0;
  private canaryTokens = new Map<string, string>(); // sessionId → token

  constructor(config: AgentFortressConfig = {}) {
    this.config = {
      apiKey: '',
      serverUrl: '',
      mode: 'local',
      logLevel: 'info',
      blockThreshold: 0.70,
      alertThreshold: 0.35,
      throwOnBlock: false,
      velocityLimit: 5,
      velocityWindowMs: 60_000,
      scanOutputs: true,
      blockMessage: '[AgentFortress] Input blocked: potential prompt injection or policy violation.',
      shadowMode: false,
      ...config,
    };
    this.sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Scan a string for threats. Returns a PolicyAction with action, score, and threat details.
   */
  scan(text: string, direction: 'input' | 'output' = 'input'): PolicyAction {
    const isOutput = direction === 'output';
    let result = advancedScan(text, this.config.blockThreshold, this.config.alertThreshold, isOutput);

    // Apply session-level accumulated risk boost (input only)
    if (!isOutput && result.score !== undefined) {
      const accumulatedBoost = this.tracker.record(this.sessionId, result, this.config.velocityWindowMs);
      if (accumulatedBoost > 0 && result.score > 0) {
        const boostedScore = Math.min(result.score + accumulatedBoost, 1.0);
        const newAction = boostedScore >= this.config.blockThreshold ? 'block' : boostedScore >= this.config.alertThreshold ? 'alert' : result.action;
        result = { ...result, score: Math.round(boostedScore * 1000) / 1000, action: newAction, reason: (result.reason ?? '') + ` | +session_context_boost(${accumulatedBoost.toFixed(2)})` };
      }
    }

    // Velocity limit check (input only)
    if (!isOutput) {
      const velocity = this.tracker.velocityCount(this.sessionId);
      if (velocity >= this.config.velocityLimit) {
        result = { action: 'block', score: 1.0, reason: `Velocity limit reached: ${velocity} suspicious queries in ${this.config.velocityWindowMs}ms window`, threats: result.threats };
      }
    }

    // Add fingerprint and MITRE technique
    if (result.threats && result.threats.length > 0) {
      const fp = computeFingerprint(result.threats);
      const { isNovel, count } = this.tracker.recordFingerprint(this.sessionId, fp);
      result = {
        ...result,
        fingerprint: fp,
        mitreTechnique: getMitreForThreats(result.threats),
        isNovel,
        similarAttackCount: count,
      };
    }

    // Apply custom rules (can override in both directions)
    result = this._applyCustomRules(result);

    // Shadow mode: never actually block
    if (this.config.shadowMode && (result.action === 'block' || result.action === 'alert')) {
      result = { ...result, action: 'shadow_allow', isShadow: true };
    }

    // Emit threat/audit events
    if (result.action !== 'allow' && result.action !== 'shadow_allow' && result.threats?.length) {
      const top = result.threats.sort((a, b) => b.confidence - a.confidence)[0];
      this._emitThreat({
        id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: Date.now(),
        type: top.category,
        severity: result.score! >= 0.85 ? 'critical' : result.score! >= 0.70 ? 'high' : result.score! >= 0.35 ? 'medium' : 'low',
        description: result.reason ?? top.reason,
        sessionId: this.sessionId,
      });
    }

    this._emitAudit({
      timestamp: Date.now(),
      sessionId: this.sessionId,
      direction,
      text,
      decision: result,
      isShadow: result.isShadow,
      fingerprint: result.fingerprint,
      mitreTechnique: result.mitreTechnique,
    });
    this._log('debug', `[scan/${direction}] score=${result.score} action=${result.action} reason="${result.reason ?? 'none'}"`);

    return result;
  }

  /**
   * Scan multiple segments with trust levels.
   */
  scanSegmented(segments: SegmentInput[]): SegmentedScanResult {
    const results: SegmentResult[] = [];
    let worstAction: 'allow' | 'block' | 'alert' | 'shadow_allow' = 'allow';
    let worstScore = 0;
    const allThreats: Array<{ category: string; confidence: number; reason: string }> = [];

    for (const seg of segments) {
      if (seg.trust === 'trusted') {
        // Skip or lower threshold significantly
        results.push({ segment: seg, decision: { action: 'allow', score: 0, reason: 'Trusted segment skipped' }, skipped: true });
        continue;
      }

      let blockThreshold = this.config.blockThreshold;
      let alertThreshold = this.config.alertThreshold;

      if (seg.trust === 'external') {
        // External content is MORE suspicious — lower thresholds
        blockThreshold = 0.50;
        alertThreshold = 0.25;
      }

      const result = advancedScan(seg.text, blockThreshold, alertThreshold, false);
      results.push({ segment: seg, decision: result });

      if (result.score! > worstScore) worstScore = result.score!;
      if (result.action === 'block') worstAction = 'block';
      else if (result.action === 'alert' && worstAction !== 'block') worstAction = 'alert';

      if (result.threats) allThreats.push(...result.threats);
    }

    const overall: PolicyAction = {
      action: worstAction,
      score: Math.round(worstScore * 1000) / 1000,
      threats: allThreats.length > 0 ? allThreats : undefined,
      reason: worstAction !== 'allow' ? `Worst segment: ${worstAction}` : 'All segments clean',
    };

    return { segments: results, overall };
  }

  /**
   * Generate a canary token to embed in system prompt.
   */
  generateCanaryToken(sessionId?: string): string {
    const sid = sessionId ?? this.sessionId;
    const entropy = `${Date.now()}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
    const tokenHash = simpleHash(entropy).slice(0, 8);
    const token = `[CANARY:${tokenHash}:${sid.slice(0, 12)}]`;
    this.canaryTokens.set(sid, token);
    return token;
  }

  /**
   * Check if agent output contains a leaked canary token.
   */
  checkCanaryLeak(outputText: string, sessionId?: string): boolean {
    const sid = sessionId ?? this.sessionId;
    const token = this.canaryTokens.get(sid);
    if (!token) return false;
    return outputText.includes(token);
  }

  /**
   * Redact sensitive information from text.
   */
  redact(text: string): RedactionResult {
    const findings: RedactionFinding[] = [];
    let result = text;
    let offset = 0;

    // We process replacements in order to avoid overlapping issues
    const replacements: Array<{ start: number; end: number; replacement: string; type: RedactionFinding['type']; original: string }> = [];

    const addMatches = (re: RegExp, type: RedactionFinding['type'], replacement: string) => {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        replacements.push({ start: m.index, end: m.index + m[0].length, replacement, type, original: m[0] });
      }
    };

    // Order matters: more specific first
    addMatches(/\b(sk-[a-zA-Z0-9-]{20,}|AIza[0-9A-Za-z\-_]{35}|xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})\b/g, 'api_key', '[API_KEY_REDACTED]');
    addMatches(/\b(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|ghs_[a-zA-Z0-9]{20,})\b/g, 'secret_token', '[SECRET_TOKEN_REDACTED]');
    addMatches(/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b/g, 'credit_card', '[CREDIT_CARD_REDACTED]');
    addMatches(/\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g, 'ssn', '[SSN_REDACTED]');
    addMatches(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b/g, 'email', '[EMAIL_REDACTED]');

    // Sort by start index, remove overlapping (keep first)
    replacements.sort((a, b) => a.start - b.start);
    const nonOverlapping: typeof replacements = [];
    let lastEnd = -1;
    for (const r of replacements) {
      if (r.start >= lastEnd) {
        nonOverlapping.push(r);
        lastEnd = r.end;
      }
    }

    // Build result string
    let out = '';
    let cursor = 0;
    for (const r of nonOverlapping) {
      out += text.slice(cursor, r.start);
      findings.push({ type: r.type, original: r.original, replacement: r.replacement, index: r.start + offset });
      out += r.replacement;
      offset += r.replacement.length - r.original.length;
      cursor = r.end;
    }
    out += text.slice(cursor);

    return { redacted: out, findings };
  }

  /**
   * Add a custom policy rule that can override scanner decisions.
   */
  addRule(rule: CustomRule): this {
    this.customRules.push(rule);
    return this;
  }

  /**
   * Remove a custom rule by ID.
   */
  removeRule(id: string): this {
    this.customRules = this.customRules.filter(r => r.id !== id);
    return this;
  }

  /**
   * Set the tool call policy.
   */
  setToolPolicy(policy: ToolPolicy): this {
    this.toolPolicy = policy;
    this.toolCallCount = 0;
    return this;
  }

  /**
   * Check if a tool call is allowed.
   */
  checkToolCall(toolName: string, args?: Record<string, unknown>): ToolCallDecision {
    const policy = this.toolPolicy;

    if (!policy) {
      return { action: 'allow', reason: 'No tool policy configured' };
    }

    // Deny list check
    if (policy.denyList && policy.denyList.includes(toolName)) {
      return { action: 'block', reason: `Tool ${toolName} is in deny list` };
    }

    // Allow list check (if defined, only allow listed tools)
    if (policy.allowList && policy.allowList.length > 0 && !policy.allowList.includes(toolName)) {
      return { action: 'block', reason: `Tool ${toolName} is not in allow list` };
    }

    // Max calls per turn
    this.toolCallCount++;
    if (policy.maxCallsPerTurn !== undefined && this.toolCallCount > policy.maxCallsPerTurn) {
      return { action: 'block', reason: `Max tool calls per turn (${policy.maxCallsPerTurn}) exceeded` };
    }

    // Require approval check
    if (policy.requireApproval && policy.requireApproval.includes(toolName)) {
      return { action: 'require_approval', reason: `Tool ${toolName} requires approval` };
    }

    // Scan args for suspicious content
    if (args) {
      const argText = Object.values(args).filter(v => typeof v === 'string').join(' ');
      if (argText) {
        const result = advancedScan(argText, this.config.blockThreshold, this.config.alertThreshold, false);
        if (result.action === 'block' || result.action === 'alert') {
          return { action: 'alert', reason: `Tool call contains suspicious content` };
        }
      }
    }

    return { action: 'allow', reason: `Tool ${toolName} is allowed` };
  }

  /**
   * Scan RAG/retrieved context for poisoned chunks.
   */
  scanContext(input: ContextScanInput): ContextScanResult {
    const poisonedChunks: PoisonedChunkResult[] = [];
    let overallDecision: 'allow' | 'block' | 'alert' = 'allow';

    // External content is more suspicious — lower thresholds
    const blockThreshold = 0.50;
    const alertThreshold = 0.25;

    if (input.retrievedChunks) {
      for (const chunk of input.retrievedChunks) {
        const result = advancedScan(chunk.content, blockThreshold, alertThreshold, false);
        if (result.action !== 'allow') {
          poisonedChunks.push({ ...chunk, decision: result });
          if (result.action === 'block') overallDecision = 'block';
          else if (result.action === 'alert' && overallDecision !== 'block') overallDecision = 'alert';
        }
      }
    }

    // Also scan user message with normal thresholds
    if (input.userMessage) {
      const userResult = advancedScan(input.userMessage, this.config.blockThreshold, this.config.alertThreshold, false);
      if (userResult.action === 'block') overallDecision = 'block';
      else if (userResult.action === 'alert' && overallDecision !== 'block') overallDecision = 'alert';
    }

    return {
      clean: poisonedChunks.length === 0,
      poisonedChunks,
      decision: overallDecision,
    };
  }

  /**
   * Detailed scan with full layer breakdown and MITRE mapping.
   */
  scanDetailed(text: string): DetailedScanReport {
    const internals = advancedScanInternal(text, this.config.blockThreshold, this.config.alertThreshold, false);
    let result = internals.result;

    // Session context boost
    const accumulatedBoost = this.tracker.record(this.sessionId, result, this.config.velocityWindowMs);
    const priorThreats = this.tracker.get(this.sessionId).turnThreats.length;
    if (accumulatedBoost > 0 && result.score! > 0) {
      const boostedScore = Math.min(result.score! + accumulatedBoost, 1.0);
      const newAction = boostedScore >= this.config.blockThreshold ? 'block' : boostedScore >= this.config.alertThreshold ? 'alert' : result.action;
      result = { ...result, score: Math.round(boostedScore * 1000) / 1000, action: newAction };
    }

    // Velocity
    const velocityCount = this.tracker.velocityCount(this.sessionId);
    const velocityTriggered = velocityCount >= this.config.velocityLimit;

    // Fingerprint
    const fp = result.threats ? computeFingerprint(result.threats) : '';
    const { isNovel, count } = fp ? this.tracker.recordFingerprint(this.sessionId, fp) : { isNovel: true, count: 0 };

    // Custom rules
    const customRuleResults: Array<{ ruleId: string; applied: boolean; action?: string }> = [];
    for (const rule of this.customRules) {
      const applies = rule.condition(result);
      customRuleResults.push({ ruleId: rule.id, applied: applies, action: applies ? rule.action : undefined });
    }
    result = this._applyCustomRules(result);

    // Shadow mode
    if (this.config.shadowMode && (result.action === 'block' || result.action === 'alert')) {
      result = { ...result, action: 'shadow_allow', isShadow: true };
    }

    const mitreTechnique = result.threats ? getMitreForThreats(result.threats) : '';
    const score = result.score ?? 0;

    const recommendation =
      result.action === 'block' || result.action === 'shadow_allow' && score >= this.config.blockThreshold
        ? `Block this request. High-confidence ${result.threats?.[0]?.category ?? 'threat'} attempt.`
        : result.action === 'alert'
        ? `Alert: suspicious content detected. Review before allowing.`
        : 'Request appears clean. Allow.';

    return {
      ...result,
      fingerprint: fp,
      isNovel,
      similarAttackCount: count,
      mitreTechnique,
      layers: {
        normalization: {
          applied: internals.normalizationApplied,
          normalized: internals.normalized,
        },
        patterns: internals.patternThreats,
        semantic: internals.semanticThreats.map(t => ({ category: t.category, confidence: t.confidence })),
        structural: {
          charSepDetected: internals.charSepDetected,
          highEntropyTokens: internals.highEntropyCount,
          structuralScore: internals.structuralScoreVal,
        },
        sessionContext: {
          boost: accumulatedBoost,
          priorThreats,
        },
        velocity: {
          count: velocityCount,
          limit: this.config.velocityLimit,
          triggered: velocityTriggered,
        },
        customRules: customRuleResults,
      },
      recommendation,
    };
  }

  /**
   * Get session risk profile.
   */
  getSessionRisk(sessionId?: string): SessionRiskProfile {
    const sid = sessionId ?? this.sessionId;
    return this.tracker.getSessionRisk(sid);
  }

  /**
   * Wrap an agent function with pre-call input scanning AND optional post-call output scanning.
   */
  protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
    const self = this;
    return (async (...args: unknown[]) => {
      const stringArgs = self._extractStrings(args);
      for (const text of stringArgs) {
        if (!text.trim()) continue;
        const inputResult = self.scan(text, 'input');
        if (inputResult.action === 'block') {
          self._log('warn', `[protect] BLOCKED agent=${agentId ?? 'unknown'} score=${inputResult.score} reason="${inputResult.reason}"`);
          self._emitThreat({
            id: `evt-${Date.now()}`,
            timestamp: Date.now(),
            type: 'input_blocked',
            severity: 'high',
            description: `Input blocked before agent execution. Score: ${inputResult.score}. Reason: ${inputResult.reason}`,
            agentId,
            sessionId: self.sessionId,
            payload: { score: inputResult.score, threats: inputResult.threats },
          });
          if (self.config.throwOnBlock) {
            throw new Error(self.config.blockMessage);
          }
          return self.config.blockMessage;
        }
        if (inputResult.action === 'alert') {
          self._log('warn', `[protect] ALERT (passing through) agent=${agentId ?? 'unknown'} score=${inputResult.score}`);
        }
      }

      self._log('info', `Agent ${agentId ?? 'unknown'} invoked`);
      let output: unknown;
      try {
        output = agent(...args);
        if (output instanceof Promise) output = await output;
      } catch (error) {
        self._emitThreat({
          id: `evt-${Date.now()}`,
          timestamp: Date.now(),
          type: 'agent_error',
          severity: 'medium',
          description: `Agent error: ${error}`,
          agentId,
          sessionId: self.sessionId,
        });
        throw error;
      }

      if (self.config.scanOutputs && typeof output === 'string' && output.trim()) {
        const outputResult = self.scan(output, 'output');
        if (outputResult.action !== 'allow') {
          self._log('warn', `[protect] OUTPUT ALERT agent=${agentId ?? 'unknown'} score=${outputResult.score} reason="${outputResult.reason}"`);
        }
      }

      return output;
    }) as T;
  }

  /**
   * Register a threat event handler (called on block/alert decisions).
   */
  onThreat(handler: ThreatHandler): this {
    this.threatHandlers.push(handler);
    return this;
  }

  /**
   * Register an audit handler (called for every scan — allow, alert, or block).
   */
  onAudit(handler: AuditHandler): this {
    this.auditHandlers.push(handler);
    return this;
  }

  getSessionId(): string { return this.sessionId; }

  /**
   * Reset session threat accumulator.
   */
  resetSession(): void {
    this.tracker.clear(this.sessionId);
    this.sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  /**
   * Scan output text only (convenience wrapper around scan(text, 'output')).
   */
  scanOutput(text: string): PolicyAction {
    return this.scan(text, 'output');
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private _applyCustomRules(result: PolicyAction): PolicyAction {
    for (const rule of this.customRules) {
      if (rule.condition(result)) {
        return { ...result, action: rule.action, reason: rule.reason };
      }
    }
    return result;
  }

  /** Recursively extract all string values from args */
  private _extractStrings(value: unknown, depth = 0): string[] {
    if (depth > 5) return [];
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) return value.flatMap(v => this._extractStrings(v, depth + 1));
    if (value !== null && typeof value === 'object') {
      return Object.values(value).flatMap(v => this._extractStrings(v, depth + 1));
    }
    return [];
  }

  private _emitThreat(event: ThreatEvent): void {
    this.threatHandlers.forEach(h => { try { h(event); } catch { /* swallow */ } });
    this._log('warn', `[THREAT] ${event.type}: ${event.description}`);
  }

  private _emitAudit(record: AuditRecord): void {
    this.auditHandlers.forEach(h => { try { h(record); } catch { /* swallow */ } });
  }

  private _log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    const levels = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };
    if (levels[level] <= levels[this.config.logLevel]) {
      const prefix = `[AgentFortress] [${level.toUpperCase()}]`;
      if (level === 'error') console.error(prefix, message);
      else if (level === 'warn') console.warn(prefix, message);
      else console.log(prefix, message);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton convenience API
// ─────────────────────────────────────────────────────────────────────────────

let _instance: AgentFortress | null = null;

export function init(config: AgentFortressConfig = {}): AgentFortress {
  _instance = new AgentFortress(config);
  return _instance;
}

export function getInstance(): AgentFortress {
  if (!_instance) _instance = new AgentFortress();
  return _instance;
}

export function scan(text: string, direction?: 'input' | 'output'): PolicyAction {
  return getInstance().scan(text, direction);
}

export function protect<T extends (...args: unknown[]) => unknown>(agent: T, agentId?: string): T {
  return getInstance().protect(agent, agentId);
}

export default { AgentFortress, init, getInstance, scan, protect };
