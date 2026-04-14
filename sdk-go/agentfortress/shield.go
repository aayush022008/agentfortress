// Package agentfortress provides runtime protection and security monitoring for AI agents.
// The CrowdStrike for AI Agents — v2.0.0
package agentfortress

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

// VERSION is the current SDK version
const VERSION = "2.0.0"

// Config holds configuration for AgentFortress
type Config struct {
	APIKey         string
	ServerURL      string
	Mode           string  // "local" or "remote"
	LogLevel       string  // "debug", "info", "warn", "error"
	ThrowOnBlock   bool
	BlockThreshold float64 // 0–1, default 0.70
	AlertThreshold float64 // 0–1, default 0.35
	VelocityLimit  int     // suspicious queries per window, default 5
	VelocityWindow int     // seconds, default 60
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Mode:           "local",
		LogLevel:       "info",
		BlockThreshold: 0.70,
		AlertThreshold: 0.35,
		VelocityLimit:  5,
		VelocityWindow: 60,
	}
}

// ThreatSeverity represents threat severity level
type ThreatSeverity string

const (
	SeverityLow      ThreatSeverity = "low"
	SeverityMedium   ThreatSeverity = "medium"
	SeverityHigh     ThreatSeverity = "high"
	SeverityCritical ThreatSeverity = "critical"
)

// PolicyActionKind represents what action to take
type PolicyActionKind string

const (
	ActionAllow     PolicyActionKind = "allow"
	ActionBlock     PolicyActionKind = "block"
	ActionAlert     PolicyActionKind = "alert"
	ActionRateLimit PolicyActionKind = "rate_limit"
)

// Direction of the scan
type Direction string

const (
	DirectionInput  Direction = "input"
	DirectionOutput Direction = "output"
)

// ThreatEvent represents a detected security event
type ThreatEvent struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	ThreatType  string         `json:"threat_type"`
	Severity    ThreatSeverity `json:"severity"`
	Description string         `json:"description"`
	SessionID   string         `json:"session_id,omitempty"`
	AgentID     string         `json:"agent_id,omitempty"`
}

// PolicyAction is the result of scanning text
type PolicyAction struct {
	Action PolicyActionKind `json:"action"`
	Reason string           `json:"reason,omitempty"`
	Score  float64          `json:"score"`
}

// IsAllowed returns true if the action is allow
func (p PolicyAction) IsAllowed() bool { return p.Action == ActionAllow }

// IsBlocked returns true if the action is block
func (p PolicyAction) IsBlocked() bool { return p.Action == ActionBlock }

// AuditEvent is fired on every scan
type AuditEvent struct {
	Timestamp time.Time        `json:"timestamp"`
	SessionID string           `json:"session_id"`
	Direction Direction        `json:"direction"`
	Text      string           `json:"text"`
	Decision  PolicyActionKind `json:"decision"`
	Score     float64          `json:"score"`
	Reason    string           `json:"reason"`
}

// ThreatHandler is a callback for threat events
type ThreatHandler func(event ThreatEvent)

// AuditHandler is a callback for every scan
type AuditHandler func(event AuditEvent)

// BlockedError is returned/panic'd when ThrowOnBlock is set
type BlockedError struct {
	Message   string
	Direction Direction
}

func (e *BlockedError) Error() string { return e.Message }

// ── Homoglyph + leet normalization ───────────────────────────────────────────

var homoglyphs = map[rune]rune{
	// Cyrillic
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
	'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'у': 'u', 'У': 'U',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
	'τ': 't', 'υ': 'u', 'ν': 'v', 'ω': 'w',
}

var leet = map[rune]rune{
	'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
	'6': 'g', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
}

var zeroWidthChars = map[rune]bool{
	'\u200b': true, '\u200c': true, '\u200d': true,
	'\u200e': true, '\u200f': true, '\u00ad': true, '\ufeff': true,
}

// Full-width Latin: Ａ-Ｚ (U+FF21-FF3A), ａ-ｚ (U+FF41-FF5A)
func fullwidthToASCII(r rune) (rune, bool) {
	if r >= 0xFF21 && r <= 0xFF3A {
		return r - 0xFF21 + 'A', true
	}
	if r >= 0xFF41 && r <= 0xFF5A {
		return r - 0xFF41 + 'a', true
	}
	return r, false
}

var sepBetweenLetters = regexp.MustCompile(`([a-z])[-._*]([a-z])`)

func normalize(text string) string {
	// 1. Apply homoglyphs and zero-width removal
	var sb strings.Builder
	for _, r := range text {
		if zeroWidthChars[r] {
			continue
		}
		if ascii, ok := fullwidthToASCII(r); ok {
			sb.WriteRune(ascii)
			continue
		}
		if rep, ok := homoglyphs[r]; ok {
			sb.WriteRune(rep)
			continue
		}
		sb.WriteRune(r)
	}
	text = sb.String()

	// 2. Lowercase
	text = strings.ToLower(text)

	// 3. Leet-speak decode
	var lb strings.Builder
	for _, r := range text {
		if rep, ok := leet[r]; ok {
			lb.WriteRune(rep)
		} else {
			lb.WriteRune(r)
		}
	}
	text = lb.String()

	// 4. Strip char-separators between letters (only [-._*], NOT spaces)
	for sepBetweenLetters.MatchString(text) {
		text = sepBetweenLetters.ReplaceAllString(text, "$1$2")
	}

	// 5. Collapse whitespace
	text = strings.Join(strings.Fields(text), " ")

	return text
}

func isLetter(r rune) bool {
	return unicode.IsLetter(r)
}

// ── Pattern library ───────────────────────────────────────────────────────────

type scanPattern struct {
	name       string
	confidence float64
	re         *regexp.Regexp
}

var inputPatterns = []scanPattern{
	// Instruction override
	{name: "instruction_override", confidence: 0.95,
		re: regexp.MustCompile(`(?i)\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|constraints?|guidelines?)`)},
	{name: "instruction_override", confidence: 0.95,
		re: regexp.MustCompile(`(?i)\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)`)},
	// Soft bypass
	{name: "soft_bypass", confidence: 0.80,
		re: regexp.MustCompile(`(?i)\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b`)},
	// Jailbreaks
	{name: "jailbreak", confidence: 0.98,
		re: regexp.MustCompile(`(?i)\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?)`)},
	{name: "jailbreak", confidence: 0.88,
		re: regexp.MustCompile(`(?i)\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b`)},
	{name: "jailbreak", confidence: 0.92,
		re: regexp.MustCompile(`(?i)\b(for\s+(a\s+)?(novel|story|game|book|fiction|roleplay)|my\s+(grandmother|grandma))\b.{0,100}\b(synthesize|manufacture|make|create)\b.{0,60}\b(drug|weapon|explosive|malware|bomb)`)},
	// Role manipulation
	{name: "role_manip", confidence: 0.88,
		re: regexp.MustCompile(`(?i)\byou\s+(are\s+now|have\s+become)\b.{0,60}\b(different|new|another)\b.{0,30}\b(ai|model|assistant)`)},
	// Token smuggling / LLaMA / ChatML
	{name: "token_smuggling", confidence: 0.92,
		re: regexp.MustCompile(`(?i)(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\|user\|>|<\|assistant\|>)`)},
	// Scope creep
	{name: "scope_creep", confidence: 0.95,
		re: regexp.MustCompile(`(?i)rm\s+-rf|drop\s+table|truncate\s+table`)},
	{name: "scope_creep", confidence: 0.90,
		re: regexp.MustCompile(`(?i)(access|read|open|list).{0,40}(/etc/passwd|\.ssh/|\.aws/|\.env|id_rsa|credentials?)`)},
	// Data exfil
	{name: "data_exfil", confidence: 0.90,
		re: regexp.MustCompile(`(?i)(exfiltrate|exfil|send\s+to\s+https?|POST\s+to|upload\s+to\s+https?)`)},
	// Prompt leak
	{name: "prompt_leak", confidence: 0.88,
		re: regexp.MustCompile(`(?i)(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are)).{0,40}(your\s+(system\s+prompt|instructions?|prompt|context))`)},
	// Indirect injection
	{name: "indirect_inject", confidence: 0.88,
		re: regexp.MustCompile(`(?i)"(instruction|system_prompt|prompt|role)"\s*:\s*"[^"]{0,200}(ignore|disregard|bypass|override|forget)[^"]{0,200}"`)},
	{name: "indirect_inject", confidence: 0.85,
		re: regexp.MustCompile("(?is)```[^`]{0,500}(ignore\\s+(previous|all|above)|disregard\\s+(your|all)|forget\\s+everything)[^`]{0,500}```")},
	// Classic
	{name: "classic", confidence: 0.90,
		re: regexp.MustCompile(`(?i)\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b`)},
	// Reverse psychology
	{name: "reverse_psychology", confidence: 0.85,
		re: regexp.MustCompile(`(?i)\bwhatever\s+you\s+do\b.{0,30}\b(don.t|do\s+not)\b.{0,30}\b(follow|obey)\b.{0,30}\b(instructions?|rules?)`)},
	// Real/actual instructions injection
	{name: "instruction_override", confidence: 0.88,
		re: regexp.MustCompile(`(?i)\b(your\s+(real|actual|true)\s+instructions?\s+(are|follow)|actual\s+instructions?\s+are)`)},
	// SYSTEM:/USER:/ASSISTANT: prefix injection
	{name: "prompt_injection", confidence: 0.88,
		re: regexp.MustCompile(`(?im)^\s*(SYSTEM\s*:\s*|USER\s*:\s*|ASSISTANT\s*:\s*)`)},
	// Unicode RTL override
	{name: "token_smuggling", confidence: 0.85,
		re: regexp.MustCompile(`[\x{202E}\x{202D}\x{202C}\x{202B}\x{202A}\x{200F}\x{200E}]`)},
	// Null byte injection
	{name: "token_smuggling", confidence: 0.80,
		re: regexp.MustCompile(`\x00`)},
	// Multi-language injections
	{name: "instruction_override", confidence: 0.90,
		re: regexp.MustCompile(`(?i)(ignorez\s+toutes\s+les\s+instructions|ignoriere\s+alle\s+(vorherigen\s+)?anweisungen|ignora\s+todas\s+las\s+instrucciones)`)},
}

var outputPatterns = []scanPattern{
	{name: "secret_leakage", confidence: 0.95,
		re: regexp.MustCompile(`sk-[a-zA-Z0-9\-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}`)},
	{name: "pii_credit_card", confidence: 0.90,
		re: regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b`)},
	{name: "pii_ssn", confidence: 0.85,
		re: regexp.MustCompile(`\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b`)},
	{name: "pii_email", confidence: 0.70,
		re: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	{name: "secret_leakage", confidence: 0.88,
		re: regexp.MustCompile(`(?i)(password|passwd|secret|api_key|access_token|auth_token)\s*[=:]\s*\S{8,}`)},
}

// ── Scanner ───────────────────────────────────────────────────────────────────

func scanInput(text string, blockThreshold, alertThreshold float64) PolicyAction {
	norm := normalize(text)
	variants := []string{strings.ToLower(text), norm}

	maxConf := 0.0
	reason := ""
	for _, v := range variants {
		for _, p := range inputPatterns {
			if p.re.MatchString(v) && p.confidence > maxConf {
				maxConf = p.confidence
				reason = p.name
			}
		}
	}

	action := ActionAllow
	if maxConf >= blockThreshold {
		action = ActionBlock
	} else if maxConf >= alertThreshold {
		action = ActionAlert
	}

	return PolicyAction{Action: action, Score: maxConf, Reason: reason}
}

func scanOutput(text string, blockThreshold, alertThreshold float64) PolicyAction {
	maxConf := 0.0
	reason := ""
	for _, p := range outputPatterns {
		if p.re.MatchString(text) && p.confidence > maxConf {
			maxConf = p.confidence
			reason = p.name
		}
	}

	action := ActionAllow
	if maxConf >= blockThreshold {
		action = ActionBlock
	} else if maxConf >= alertThreshold {
		action = ActionAlert
	}

	return PolicyAction{Action: action, Score: maxConf, Reason: reason}
}

// ── Shield ────────────────────────────────────────────────────────────────────

// Shield is the main AgentFortress instance
type Shield struct {
	config              Config
	sessionID           string
	mu                  sync.Mutex
	handlers            []ThreatHandler
	auditHandlers       []AuditHandler
	suspiciousTimes     []int64 // unix nanos
	sessionThreatScore  float64
	turnCount           int
}

// New creates a new Shield instance
func New(cfg Config) *Shield {
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 0.70
	}
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 0.35
	}
	if cfg.VelocityLimit == 0 {
		cfg.VelocityLimit = 5
	}
	if cfg.VelocityWindow == 0 {
		cfg.VelocityWindow = 60
	}
	return &Shield{
		config:    cfg,
		sessionID: fmt.Sprintf("session-%d", time.Now().UnixMilli()),
	}
}

// Default creates a Shield with default config
func Default() *Shield {
	return New(DefaultConfig())
}

// ResetSession clears accumulated session context
func (s *Shield) ResetSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionID = fmt.Sprintf("session-%d", time.Now().UnixMilli())
	s.suspiciousTimes = nil
	s.sessionThreatScore = 0
	s.turnCount = 0
}

// Scan checks text for prompt injection or threats
func (s *Shield) Scan(text string) PolicyAction {
	result := scanInput(text, s.config.BlockThreshold, s.config.AlertThreshold)
	s.fireAudit(AuditEvent{
		Timestamp: time.Now(),
		SessionID: s.sessionID,
		Direction: DirectionInput,
		Text:      truncate(text, 500),
		Decision:  result.Action,
		Score:     result.Score,
		Reason:    result.Reason,
	})
	if result.IsBlocked() {
		s.emitThreat(ThreatEvent{
			ID:          fmt.Sprintf("evt-%d", time.Now().UnixMilli()),
			Timestamp:   time.Now(),
			ThreatType:  "prompt_injection",
			Severity:    SeverityHigh,
			Description: result.Reason,
			SessionID:   s.sessionID,
		})
	}
	return result
}

// ScanOutput scans output text for secrets/PII
func (s *Shield) ScanOutput(text string) PolicyAction {
	result := scanOutput(text, s.config.BlockThreshold, s.config.AlertThreshold)
	s.fireAudit(AuditEvent{
		Timestamp: time.Now(),
		SessionID: s.sessionID,
		Direction: DirectionOutput,
		Text:      truncate(text, 500),
		Decision:  result.Action,
		Score:     result.Score,
		Reason:    result.Reason,
	})
	return result
}

// Protect wraps an agent function with input+output scanning, velocity limiting,
// and context accumulation. agentFn receives the original args and returns (result, error).
func (s *Shield) Protect(agentFn func(args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	s.mu.Lock()
	s.turnCount++
	s.mu.Unlock()

	// Velocity check
	if s.checkVelocity() {
		msg := "[AgentFortress] Rate limit exceeded: too many suspicious queries."
		s.fireAudit(AuditEvent{
			Timestamp: time.Now(),
			SessionID: s.sessionID,
			Direction: DirectionInput,
			Text:      "",
			Decision:  ActionBlock,
			Score:     1.0,
			Reason:    "velocity_limit_exceeded",
		})
		if s.config.ThrowOnBlock {
			return nil, &BlockedError{Message: msg, Direction: DirectionInput}
		}
		return msg, nil
	}

	// Extract and scan all string inputs
	texts := extractStrings(args)
	for _, t := range texts {
		result := scanInput(t, s.config.BlockThreshold, s.config.AlertThreshold)

		// Boost based on session history
		boosted := result.Score
		s.mu.Lock()
		if s.sessionThreatScore > 0 && s.turnCount > 1 {
			boost := s.sessionThreatScore * 0.1
			if boost > 0.20 {
				boost = 0.20
			}
			boosted += boost
			if boosted > 1.0 {
				boosted = 1.0
			}
		}
		if result.Score > 0 {
			s.sessionThreatScore = s.sessionThreatScore*0.8 + result.Score*0.2
			if result.Score >= s.config.AlertThreshold {
				s.suspiciousTimes = append(s.suspiciousTimes, time.Now().Unix())
			}
		}
		s.mu.Unlock()

		decision := ActionAllow
		if boosted >= s.config.BlockThreshold {
			decision = ActionBlock
		} else if boosted >= s.config.AlertThreshold {
			decision = ActionAlert
		}

		s.fireAudit(AuditEvent{
			Timestamp: time.Now(),
			SessionID: s.sessionID,
			Direction: DirectionInput,
			Text:      truncate(t, 500),
			Decision:  decision,
			Score:     boosted,
			Reason:    result.Reason,
		})

		if decision == ActionBlock {
			msg := "[AgentFortress] Request blocked: potential security threat detected."
			if s.config.ThrowOnBlock {
				return nil, &BlockedError{Message: msg, Direction: DirectionInput}
			}
			return msg, nil
		}
	}

	// Call the agent
	res, err := agentFn(args...)
	if err != nil {
		return nil, err
	}

	// Scan output
	if resStr, ok := res.(string); ok {
		outResult := s.ScanOutput(resStr)
		if outResult.IsBlocked() {
			msg := "[AgentFortress] Output blocked: sensitive data detected."
			if s.config.ThrowOnBlock {
				return nil, &BlockedError{Message: msg, Direction: DirectionOutput}
			}
			return msg, nil
		}
	}

	return res, nil
}

// OnThreat registers a threat event handler
func (s *Shield) OnThreat(handler ThreatHandler) *Shield {
	s.handlers = append(s.handlers, handler)
	return s
}

// OnAudit registers an audit event handler (fires on every scan)
func (s *Shield) OnAudit(handler AuditHandler) *Shield {
	s.auditHandlers = append(s.auditHandlers, handler)
	return s
}

// SessionID returns the current session ID
func (s *Shield) SessionID() string {
	return s.sessionID
}

func (s *Shield) checkVelocity() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	window := int64(s.config.VelocityWindow)
	valid := s.suspiciousTimes[:0]
	for _, ts := range s.suspiciousTimes {
		if now-ts <= window {
			valid = append(valid, ts)
		}
	}
	s.suspiciousTimes = valid
	return len(s.suspiciousTimes) >= s.config.VelocityLimit
}

func (s *Shield) emitThreat(event ThreatEvent) {
	for _, h := range s.handlers {
		h(event)
	}
}

func (s *Shield) fireAudit(event AuditEvent) {
	for _, h := range s.auditHandlers {
		h(event)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func extractStrings(args []interface{}) []string {
	var out []string
	for _, a := range args {
		collectStrings(a, 0, &out)
	}
	return out
}

func collectStrings(v interface{}, depth int, out *[]string) {
	if depth > 10 {
		return
	}
	switch val := v.(type) {
	case string:
		*out = append(*out, val)
	case []interface{}:
		for _, item := range val {
			collectStrings(item, depth+1, out)
		}
	case map[string]interface{}:
		for _, item := range val {
			collectStrings(item, depth+1, out)
		}
	}
}

// Package-level singleton
var defaultShield = Default()

// Scan is a package-level convenience function
func Scan(text string) PolicyAction {
	return defaultShield.Scan(text)
}

// ScanOutput is a package-level convenience function for output scanning
func ScanOutput(text string) PolicyAction {
	return defaultShield.ScanOutput(text)
}

// Init initializes the package-level shield
func Init(cfg Config) *Shield {
	defaultShield = New(cfg)
	return defaultShield
}
