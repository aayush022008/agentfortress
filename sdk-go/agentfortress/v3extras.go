// v3extras.go — AgentShield v3.0.0: Redactor, RateLimiter, ContextAnalyzer,
// MetricsCollector, and RealTimeFeed.
package agentfortress

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// ── Redactor ─────────────────────────────────────────────────────────────────

type RedactionCategory string

const (
	RedactSSN        RedactionCategory = "ssn"
	RedactCreditCard RedactionCategory = "credit_card"
	RedactEmail      RedactionCategory = "email"
	RedactPhone      RedactionCategory = "phone"
	RedactAPIKey     RedactionCategory = "api_key"
	RedactIP         RedactionCategory = "ip_address"
	RedactJWT        RedactionCategory = "jwt_token"
	RedactCustom     RedactionCategory = "custom"
)

type RedactionEntry struct {
	Category        RedactionCategory
	OriginalPreview string
	Placeholder     string
	Count           int
}

type RedactionResult struct {
	RedactedText    string
	RedactionCount  int
	CategoriesFound []RedactionCategory
	Entries         []RedactionEntry
}

type RedactionConfig struct {
	RedactPII         bool
	RedactSecrets     bool
	Placeholder       string
	UseCategoryLabels bool
	CustomPatterns    []struct {
		Name    string
		Pattern string
	}
}

type Redactor struct {
	config   RedactionConfig
	patterns []struct {
		category RedactionCategory
		re       *regexp.Regexp
	}
}

func NewRedactor(config *RedactionConfig) *Redactor {
	r := &Redactor{}
	if config != nil {
		r.config = *config
	} else {
		r.config = RedactionConfig{
			RedactPII:     true,
			RedactSecrets: true,
			Placeholder:   "[REDACTED]",
		}
	}
	if r.config.Placeholder == "" {
		r.config.Placeholder = "[REDACTED]"
	}

	type pat struct {
		cat     RedactionCategory
		pattern string
	}
	builtins := []pat{
		{RedactSSN, `\b\d{3}-\d{2}-\d{4}\b`},
		{RedactCreditCard, `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`},
		{RedactEmail, `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`},
		{RedactPhone, `\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`},
		{RedactAPIKey, `\b(sk-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36,})\b`},
		{RedactIP, `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`},
		{RedactJWT, `\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b`},
	}
	for _, b := range builtins {
		re, err := regexp.Compile(b.pattern)
		if err == nil {
			r.patterns = append(r.patterns, struct {
				category RedactionCategory
				re       *regexp.Regexp
			}{b.cat, re})
		}
	}
	for _, cp := range r.config.CustomPatterns {
		r.AddCustomPattern(cp.Name, cp.Pattern)
	}
	return r
}

func (r *Redactor) AddCustomPattern(name, pattern string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return
	}
	r.patterns = append(r.patterns, struct {
		category RedactionCategory
		re       *regexp.Regexp
	}{RedactCustom, re})
}

func (r *Redactor) Redact(text string) RedactionResult {
	result := RedactionResult{RedactedText: text}
	categorySet := map[RedactionCategory]bool{}
	entryMap := map[RedactionCategory]*RedactionEntry{}

	for _, p := range r.patterns {
		// skip PII-only categories if not enabled
		isPII := p.category == RedactSSN || p.category == RedactEmail || p.category == RedactPhone || p.category == RedactCreditCard
		isSecret := p.category == RedactAPIKey || p.category == RedactJWT
		if isPII && !r.config.RedactPII {
			continue
		}
		if isSecret && !r.config.RedactSecrets {
			continue
		}

		placeholder := r.config.Placeholder
		if r.config.UseCategoryLabels {
			placeholder = fmt.Sprintf("[%s]", strings.ToUpper(string(p.category)))
		}

		matches := p.re.FindAllString(result.RedactedText, -1)
		if len(matches) == 0 {
			continue
		}
		result.RedactedText = p.re.ReplaceAllString(result.RedactedText, placeholder)
		categorySet[p.category] = true
		result.RedactionCount += len(matches)

		if _, exists := entryMap[p.category]; !exists {
			preview := matches[0]
			if len(preview) > 10 {
				preview = preview[:4] + "***"
			}
			entryMap[p.category] = &RedactionEntry{
				Category:        p.category,
				OriginalPreview: preview,
				Placeholder:     placeholder,
				Count:           len(matches),
			}
		} else {
			entryMap[p.category].Count += len(matches)
		}
	}

	for cat := range categorySet {
		result.CategoriesFound = append(result.CategoriesFound, cat)
		result.Entries = append(result.Entries, *entryMap[cat])
	}
	return result
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

type RateLimitConfig struct {
	RequestsPerMinute int
	BurstMultiplier   float64
	WindowSeconds     float64
}

type RateLimitResult struct {
	Allowed           bool
	RetryAfterSeconds float64
	Reason            string
	CurrentCount      int
	Limit             int
}

type RateLimiter struct {
	mu      sync.RWMutex
	config  RateLimitConfig
	windows map[string][]float64
}

func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	if config.WindowSeconds <= 0 {
		config.WindowSeconds = 60
	}
	if config.BurstMultiplier <= 0 {
		config.BurstMultiplier = 1.0
	}
	return &RateLimiter{
		config:  config,
		windows: make(map[string][]float64),
	}
}

func (r *RateLimiter) CheckAndConsume(sessionID, agentName string, tokens int) RateLimitResult {
	key := fmt.Sprintf("%s:%s", sessionID, agentName)
	now := float64(time.Now().UnixNano()) / 1e9
	limit := int(float64(r.config.RequestsPerMinute) * r.config.BurstMultiplier)

	r.mu.Lock()
	defer r.mu.Unlock()

	ts := r.windows[key]
	// drop old timestamps
	cutoff := now - r.config.WindowSeconds
	valid := ts[:0]
	for _, t := range ts {
		if t >= cutoff {
			valid = append(valid, t)
		}
	}

	current := len(valid)
	if current+tokens > limit {
		// earliest timestamp tells us when a slot frees up
		retryAfter := 0.0
		if len(valid) > 0 {
			retryAfter = valid[0] + r.config.WindowSeconds - now
			if retryAfter < 0 {
				retryAfter = 0
			}
		}
		r.windows[key] = valid
		return RateLimitResult{
			Allowed:           false,
			RetryAfterSeconds: retryAfter,
			Reason:            fmt.Sprintf("rate limit exceeded: %d/%d requests in window", current, limit),
			CurrentCount:      current,
			Limit:             limit,
		}
	}

	for i := 0; i < tokens; i++ {
		valid = append(valid, now)
	}
	r.windows[key] = valid
	return RateLimitResult{
		Allowed:      true,
		CurrentCount: current + tokens,
		Limit:        limit,
	}
}

func (r *RateLimiter) GetUsageStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := float64(time.Now().UnixNano()) / 1e9
	cutoff := now - r.config.WindowSeconds
	stats := map[string]interface{}{}
	for key, ts := range r.windows {
		count := 0
		for _, t := range ts {
			if t >= cutoff {
				count++
			}
		}
		stats[key] = count
	}
	return stats
}

func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.windows, key)
}

// ── ContextAnalyzer ──────────────────────────────────────────────────────────

type ContextThreatResult struct {
	ContextScore       int
	EscalationDetected bool
	PivotDetected      bool
	ChainOfConcern     []string
}

type ConversationTurn struct {
	Role        string
	Content     string
	ThreatScore int
	ToolName    string
	Timestamp   float64
}

type ContextAnalyzer struct {
	mu       sync.RWMutex
	sessions map[string][]ConversationTurn
}

func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{sessions: make(map[string][]ConversationTurn)}
}

var benignTopics = []string{"weather", "cooking", "travel", "sports"}
var sensitiveTopics = []string{"hacking", "malware", "weapons", "exploits", "bypass", "jailbreak", "injection"}

func containsAny(text string, words []string) bool {
	lower := strings.ToLower(text)
	for _, w := range words {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func (c *ContextAnalyzer) Update(sessionID, role, content string, threatScore int, toolName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	turns := c.sessions[sessionID]
	turns = append(turns, ConversationTurn{
		Role:        role,
		Content:     content,
		ThreatScore: threatScore,
		ToolName:    toolName,
		Timestamp:   float64(time.Now().UnixNano()) / 1e9,
	})
	if len(turns) > 20 {
		turns = turns[len(turns)-20:]
	}
	c.sessions[sessionID] = turns
}

func (c *ContextAnalyzer) Analyze(sessionID string) ContextThreatResult {
	c.mu.RLock()
	turns := c.sessions[sessionID]
	c.mu.RUnlock()

	result := ContextThreatResult{}
	if len(turns) == 0 {
		return result
	}

	// context score = average threat score
	total := 0
	for _, t := range turns {
		total += t.ThreatScore
	}
	result.ContextScore = total / len(turns)

	// escalation: last 3 turns strictly increasing
	if len(turns) >= 3 {
		last3 := turns[len(turns)-3:]
		if last3[0].ThreatScore < last3[1].ThreatScore && last3[1].ThreatScore < last3[2].ThreatScore {
			result.EscalationDetected = true
			result.ChainOfConcern = append(result.ChainOfConcern, "threat score escalation in last 3 turns")
		}
	}

	// pivot: benign early, sensitive recent
	mid := len(turns) / 2
	if mid > 0 {
		earlyBenign := false
		for _, t := range turns[:mid] {
			if containsAny(t.Content, benignTopics) {
				earlyBenign = true
				break
			}
		}
		recentSensitive := false
		for _, t := range turns[mid:] {
			if containsAny(t.Content, sensitiveTopics) {
				recentSensitive = true
				break
			}
		}
		if earlyBenign && recentSensitive {
			result.PivotDetected = true
			result.ChainOfConcern = append(result.ChainOfConcern, "topic pivot from benign to sensitive")
		}
	}

	return result
}

func (c *ContextAnalyzer) ClearSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, sessionID)
}

func (c *ContextAnalyzer) GetSessionRisk(sessionID string) int {
	c.mu.RLock()
	turns := c.sessions[sessionID]
	c.mu.RUnlock()
	if len(turns) == 0 {
		return 0
	}
	max := 0
	for _, t := range turns {
		if t.ThreatScore > max {
			max = t.ThreatScore
		}
	}
	return max
}

// ── MetricsCollector ─────────────────────────────────────────────────────────

type MetricType string

const (
	MetricCounter   MetricType = "counter"
	MetricGauge     MetricType = "gauge"
	MetricHistogram MetricType = "histogram"
)

type MetricData struct {
	Name    string
	Type    MetricType
	Value   float64
	Help    string
	Sum     float64
	Count   int
	Buckets map[float64]int
}

type MetricsCollector struct {
	mu      sync.RWMutex
	metrics map[string]*MetricData
}

var globalMetrics *MetricsCollector
var metricsOnce sync.Once

var histogramBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func GetMetricsInstance() *MetricsCollector {
	metricsOnce.Do(func() {
		globalMetrics = &MetricsCollector{metrics: make(map[string]*MetricData)}
		predefined := []struct {
			name  string
			mtype MetricType
			help  string
		}{
			{"agentshield_requests_total", MetricCounter, "Total number of requests processed"},
			{"agentshield_threats_detected_total", MetricCounter, "Total threats detected"},
			{"agentshield_blocked_requests_total", MetricCounter, "Total requests blocked"},
			{"agentshield_scan_duration_seconds", MetricHistogram, "Duration of scan operations"},
			{"agentshield_active_sessions", MetricGauge, "Number of active sessions"},
			{"agentshield_threat_score", MetricHistogram, "Distribution of threat scores"},
			{"agentshield_rate_limit_hits_total", MetricCounter, "Total rate limit hits"},
			{"agentshield_redactions_total", MetricCounter, "Total redactions performed"},
		}
		for _, p := range predefined {
			m := &MetricData{Name: p.name, Type: p.mtype, Help: p.help}
			if p.mtype == MetricHistogram {
				m.Buckets = make(map[float64]int)
			}
			globalMetrics.metrics[p.name] = m
		}
	})
	return globalMetrics
}

func (m *MetricsCollector) Increment(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	md, ok := m.metrics[name]
	if !ok {
		md = &MetricData{Name: name, Type: MetricCounter}
		m.metrics[name] = md
	}
	md.Value += value
}

func (m *MetricsCollector) SetGauge(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	md, ok := m.metrics[name]
	if !ok {
		md = &MetricData{Name: name, Type: MetricGauge}
		m.metrics[name] = md
	}
	md.Value = value
}

func (m *MetricsCollector) Observe(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	md, ok := m.metrics[name]
	if !ok {
		md = &MetricData{Name: name, Type: MetricHistogram, Buckets: make(map[float64]int)}
		m.metrics[name] = md
	}
	if md.Buckets == nil {
		md.Buckets = make(map[float64]int)
	}
	md.Sum += value
	md.Count++
	for _, b := range histogramBuckets {
		if value <= b {
			md.Buckets[b]++
		}
	}
	md.Buckets[math.Inf(1)]++
}

func (m *MetricsCollector) ExportPrometheus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// sort keys for deterministic output
	keys := make([]string, 0, len(m.metrics))
	for k := range m.metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		md := m.metrics[k]
		if md.Help != "" {
			fmt.Fprintf(&sb, "# HELP %s %s\n", md.Name, md.Help)
		}
		fmt.Fprintf(&sb, "# TYPE %s %s\n", md.Name, string(md.Type))
		switch md.Type {
		case MetricHistogram:
			bucketKeys := make([]float64, 0, len(md.Buckets))
			for b := range md.Buckets {
				bucketKeys = append(bucketKeys, b)
			}
			sort.Float64s(bucketKeys)
			for _, b := range bucketKeys {
				if math.IsInf(b, 1) {
					fmt.Fprintf(&sb, "%s_bucket{le=\"+Inf\"} %d\n", md.Name, md.Buckets[b])
				} else {
					fmt.Fprintf(&sb, "%s_bucket{le=\"%g\"} %d\n", md.Name, b, md.Buckets[b])
				}
			}
			fmt.Fprintf(&sb, "%s_sum %g\n", md.Name, md.Sum)
			fmt.Fprintf(&sb, "%s_count %d\n", md.Name, md.Count)
		default:
			fmt.Fprintf(&sb, "%s %g\n", md.Name, md.Value)
		}
	}
	return sb.String()
}

func (m *MetricsCollector) ExportJSON() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]interface{}, len(m.metrics))
	for k, md := range m.metrics {
		data, _ := json.Marshal(md)
		var obj interface{}
		_ = json.Unmarshal(data, &obj)
		out[k] = obj
	}
	return out
}

func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, md := range m.metrics {
		md.Value = 0
		md.Sum = 0
		md.Count = 0
		if md.Buckets != nil {
			md.Buckets = make(map[float64]int)
		}
	}
}

// ── RealTimeFeed ─────────────────────────────────────────────────────────────

type AlertSeverityLevel string

const (
	AlertCritical AlertSeverityLevel = "critical"
	AlertHigh     AlertSeverityLevel = "high"
	AlertMedium   AlertSeverityLevel = "medium"
	AlertLow      AlertSeverityLevel = "low"
	AlertInfo     AlertSeverityLevel = "info"
)

type ThreatAlertEvent struct {
	AlertID   string
	SessionID string
	Severity  AlertSeverityLevel
	Category  string
	Message   string
	Timestamp float64
	EventData map[string]interface{}
}

type RealTimeFeed struct {
	mu             sync.RWMutex
	subscribers    map[string]func(ThreatAlertEvent)
	history        []ThreatAlertEvent
	stats          map[AlertSeverityLevel]int
	totalPublished int
}

func NewRealTimeFeed() *RealTimeFeed {
	return &RealTimeFeed{
		subscribers: make(map[string]func(ThreatAlertEvent)),
		stats: map[AlertSeverityLevel]int{
			AlertCritical: 0,
			AlertHigh:     0,
			AlertMedium:   0,
			AlertLow:      0,
			AlertInfo:     0,
		},
	}
}

func (f *RealTimeFeed) Subscribe(callback func(ThreatAlertEvent)) string {
	id := newUUID()
	f.mu.Lock()
	f.subscribers[id] = callback
	f.mu.Unlock()
	return id
}

func (f *RealTimeFeed) Unsubscribe(subID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.subscribers[subID]
	if ok {
		delete(f.subscribers, subID)
	}
	return ok
}

func (f *RealTimeFeed) Publish(alert ThreatAlertEvent) {
	f.mu.Lock()
	// add to history (max 1000)
	if len(f.history) >= 1000 {
		f.history = f.history[1:]
	}
	f.history = append(f.history, alert)
	f.stats[alert.Severity]++
	f.totalPublished++
	// copy subscribers to call outside lock
	subs := make([]func(ThreatAlertEvent), 0, len(f.subscribers))
	for _, cb := range f.subscribers {
		subs = append(subs, cb)
	}
	f.mu.Unlock()

	for _, cb := range subs {
		cb(alert)
	}
}

func (f *RealTimeFeed) GetRecentAlerts(limit int) []ThreatAlertEvent {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if limit <= 0 || limit > len(f.history) {
		limit = len(f.history)
	}
	start := len(f.history) - limit
	result := make([]ThreatAlertEvent, limit)
	copy(result, f.history[start:])
	return result
}

func (f *RealTimeFeed) GetStats() map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return map[string]interface{}{
		"total_published":   f.totalPublished,
		"total_subscribers": len(f.subscribers),
		"history_size":      len(f.history),
		"by_severity": map[string]int{
			"critical": f.stats[AlertCritical],
			"high":     f.stats[AlertHigh],
			"medium":   f.stats[AlertMedium],
			"low":      f.stats[AlertLow],
			"info":     f.stats[AlertInfo],
		},
	}
}

func (f *RealTimeFeed) CreateAlert(sessionID string, severity AlertSeverityLevel, category, message string) ThreatAlertEvent {
	alert := ThreatAlertEvent{
		AlertID:   newUUID(),
		SessionID: sessionID,
		Severity:  severity,
		Category:  category,
		Message:   message,
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		EventData: map[string]interface{}{},
	}
	f.Publish(alert)
	return alert
}
