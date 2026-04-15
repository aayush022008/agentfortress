using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace AgentFortress
{
    // ══════════════════════════════════════════════════════════════════════════
    // AgentFortress v3 — Extra components
    // ChainGuard | Redactor | RateLimiter | ContextAnalyzer | MetricsCollector | RealTimeFeed
    // ══════════════════════════════════════════════════════════════════════════

    // ─── ChainGuard ───────────────────────────────────────────────────────────

    public enum AgentTrustLevel
    {
        Trusted = 0,
        Verified = 1,
        Unverified = 2,
        Suspicious = 3,
        Untrusted = 4
    }

    public record AgentNode
    {
        public string AgentId { get; init; } = "";
        public string AgentName { get; init; } = "";
        public AgentTrustLevel TrustLevel { get; set; }
        public List<string> Capabilities { get; init; } = new();
        public string? ParentId { get; init; }
        public double CreatedAt { get; init; }
        public int MessageCount { get; set; }
        public bool Flagged { get; set; }
        public string FlagReason { get; set; } = "";
    }

    public record ChainMsg
    {
        public string MessageId { get; init; } = Guid.NewGuid().ToString();
        public string FromAgent { get; init; } = "";
        public string ToAgent { get; init; } = "";
        public string ContentHash { get; init; } = "";
        public double Timestamp { get; init; }
        public AgentTrustLevel TrustLevel { get; init; }
        public bool Flagged { get; set; }
        public string FlagReason { get; set; } = "";
    }

    public class ChainGuard
    {
        private readonly Dictionary<string, AgentNode> _agents = new();
        private readonly List<ChainMsg> _messages = new();
        private readonly string _secret = Guid.NewGuid().ToString();
        private readonly object _lock = new();

        public AgentNode RegisterAgent(
            string agentId,
            string agentName,
            AgentTrustLevel trustLevel = AgentTrustLevel.Unverified,
            List<string>? capabilities = null,
            string? parentId = null)
        {
            lock (_lock)
            {
                var node = new AgentNode
                {
                    AgentId = agentId,
                    AgentName = agentName,
                    TrustLevel = trustLevel,
                    Capabilities = capabilities ?? new List<string>(),
                    ParentId = parentId,
                    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
                };
                _agents[agentId] = node;
                return node;
            }
        }

        public bool VerifyAgent(string agentId, string verificationToken)
        {
            lock (_lock)
            {
                if (!_agents.TryGetValue(agentId, out var node)) return false;
                var expected = (agentId + _secret).GetHashCode().ToString();
                if (verificationToken == expected)
                {
                    node.TrustLevel = AgentTrustLevel.Verified;
                    return true;
                }
                return false;
            }
        }

        public ChainMsg SendMessage(string fromAgent, string toAgent, string content)
        {
            lock (_lock)
            {
                AgentTrustLevel trust = AgentTrustLevel.Unverified;
                if (_agents.TryGetValue(fromAgent, out var sender))
                {
                    trust = sender.TrustLevel;
                    sender.MessageCount++;
                }

                var msg = new ChainMsg
                {
                    FromAgent = fromAgent,
                    ToAgent = toAgent,
                    ContentHash = HashContent(content),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
                    TrustLevel = trust,
                };
                _messages.Add(msg);
                return msg;
            }
        }

        public bool CheckPrivilegeEscalation(string fromAgent, string toAgent, string requestedCapability)
        {
            lock (_lock)
            {
                if (!_agents.TryGetValue(fromAgent, out var from)) return true; // unknown = escalation risk
                if (!_agents.TryGetValue(toAgent, out var to)) return false;

                // Escalation if requesting capability that the from-agent doesn't have
                // and the trust level of from is lower (higher enum value) than to
                bool fromHasCap = from.Capabilities.Contains(requestedCapability, StringComparer.OrdinalIgnoreCase);
                bool isLowerTrust = (int)from.TrustLevel > (int)to.TrustLevel;

                return !fromHasCap && isLowerTrust;
            }
        }

        public List<AgentNode> GetChain(string agentId)
        {
            lock (_lock)
            {
                var chain = new List<AgentNode>();
                var current = agentId;
                var visited = new HashSet<string>();
                while (current != null && !visited.Contains(current))
                {
                    visited.Add(current);
                    if (_agents.TryGetValue(current, out var node))
                    {
                        chain.Add(node);
                        current = node.ParentId;
                    }
                    else break;
                }
                return chain;
            }
        }

        public int GetTrustScore(string agentId)
        {
            lock (_lock)
            {
                if (!_agents.TryGetValue(agentId, out var node)) return 0;
                // TrustLevel: 0=Trusted → 100, 4=Untrusted → 0
                if (node.Flagged) return 0;
                var baseScore = (4 - (int)node.TrustLevel) * 25; // 0..100
                var msgPenalty = Math.Min(node.MessageCount / 10, 20);
                return Math.Max(0, baseScore - msgPenalty);
            }
        }

        public void FlagAgent(string agentId, string reason)
        {
            lock (_lock)
            {
                if (_agents.TryGetValue(agentId, out var node))
                {
                    node.Flagged = true;
                    node.FlagReason = reason;
                    node.TrustLevel = AgentTrustLevel.Suspicious;
                }
            }
        }

        public List<ChainMsg> GetMessageHistory(string? agentId = null, int limit = 100)
        {
            lock (_lock)
            {
                var msgs = agentId == null
                    ? _messages
                    : _messages.Where(m => m.FromAgent == agentId || m.ToAgent == agentId).ToList();
                return msgs.TakeLast(limit).ToList();
            }
        }

        private string HashContent(string content)
        {
            return Math.Abs(content.GetHashCode()).ToString("x8");
        }
    }

    // ─── Redactor ─────────────────────────────────────────────────────────────

    public enum RedactionCategory { Ssn, CreditCard, Email, Phone, ApiKey, IpAddress, JwtToken, Custom }

    public record RedactionEntry(RedactionCategory Category, string OriginalPreview, string Placeholder, int Count);

    public record RedactionResult(string RedactedText, int RedactionCount, List<RedactionCategory> CategoriesFound, List<RedactionEntry> Entries);

    public class RedactionConfig
    {
        public bool RedactPii { get; init; } = true;
        public bool RedactSecrets { get; init; } = true;
        public string Placeholder { get; init; } = "[REDACTED]";
        public bool UseCategoryLabels { get; init; } = true;
        public List<(string Name, string Pattern)> CustomPatterns { get; init; } = new();
    }

    public class Redactor
    {
        private readonly RedactionConfig _config;
        private readonly List<(RedactionCategory Category, Regex Re)> _patterns;

        public Redactor(RedactionConfig? config = null)
        {
            _config = config ?? new RedactionConfig();
            _patterns = new List<(RedactionCategory, Regex)>();

            if (_config.RedactPii)
            {
                _patterns.Add((RedactionCategory.Ssn, new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
                _patterns.Add((RedactionCategory.CreditCard, new Regex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
                _patterns.Add((RedactionCategory.Email, new Regex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
                _patterns.Add((RedactionCategory.Phone, new Regex(@"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
                _patterns.Add((RedactionCategory.IpAddress, new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
            }

            if (_config.RedactSecrets)
            {
                _patterns.Add((RedactionCategory.ApiKey, new Regex(@"\b(sk-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36,})\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
                _patterns.Add((RedactionCategory.JwtToken, new Regex(@"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+\/=]*\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)));
            }

            foreach (var (name, pattern) in _config.CustomPatterns)
            {
                try { _patterns.Add((RedactionCategory.Custom, new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled))); }
                catch { /* skip invalid */ }
            }
        }

        public RedactionResult Redact(string text)
        {
            var result = text;
            var totalCount = 0;
            var categoriesFound = new List<RedactionCategory>();
            var entries = new List<RedactionEntry>();

            foreach (var (category, re) in _patterns)
            {
                var matches = re.Matches(result);
                if (matches.Count == 0) continue;

                var placeholder = _config.UseCategoryLabels
                    ? $"[{category.ToString().ToUpperInvariant()}_REDACTED]"
                    : _config.Placeholder;

                var preview = matches[0].Value;
                if (preview.Length > 8) preview = preview[..4] + "****";

                entries.Add(new RedactionEntry(category, preview, placeholder, matches.Count));
                categoriesFound.Add(category);
                totalCount += matches.Count;
                result = re.Replace(result, placeholder);
            }

            return new RedactionResult(result, totalCount, categoriesFound, entries);
        }

        public void AddCustomPattern(string name, string pattern)
        {
            try { _patterns.Add((RedactionCategory.Custom, new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled))); }
            catch { /* skip invalid */ }
        }
    }

    // ─── RateLimiter ──────────────────────────────────────────────────────────

    public record RateLimitConfig(int RequestsPerMinute = 60, double BurstMultiplier = 1.5, double WindowSeconds = 60.0);

    public record RateLimitResult(bool Allowed, double RetryAfterSeconds, string Reason, int CurrentCount, int Limit);

    public class RateLimiter
    {
        private readonly RateLimitConfig _config;
        private readonly Dictionary<string, List<double>> _windows = new();
        private readonly object _lock = new();

        public RateLimiter(RateLimitConfig? config = null)
        {
            _config = config ?? new RateLimitConfig();
        }

        public RateLimitResult CheckAndConsume(string sessionId, string agentName = "", int tokens = 1)
        {
            lock (_lock)
            {
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
                var windowStart = now - _config.WindowSeconds;

                if (!_windows.ContainsKey(sessionId))
                    _windows[sessionId] = new List<double>();

                var window = _windows[sessionId];
                window.RemoveAll(t => t < windowStart);

                var burstLimit = (int)(_config.RequestsPerMinute * _config.BurstMultiplier);
                var currentCount = window.Count;

                if (currentCount + tokens > burstLimit)
                {
                    var oldest = window.Count > 0 ? window[0] : now;
                    var retryAfter = Math.Max(0, oldest + _config.WindowSeconds - now);
                    return new RateLimitResult(false, retryAfter, $"Rate limit exceeded: {currentCount}/{burstLimit}", currentCount, burstLimit);
                }

                for (int i = 0; i < tokens; i++)
                    window.Add(now);

                return new RateLimitResult(true, 0, "OK", currentCount + tokens, burstLimit);
            }
        }

        public Dictionary<string, int> GetUsageStats()
        {
            lock (_lock)
            {
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
                var windowStart = now - _config.WindowSeconds;
                var stats = new Dictionary<string, int>();
                foreach (var (key, window) in _windows)
                    stats[key] = window.Count(t => t >= windowStart);
                return stats;
            }
        }

        public void Reset(string? key = null)
        {
            lock (_lock)
            {
                if (key == null) _windows.Clear();
                else _windows.Remove(key);
            }
        }
    }

    // ─── ContextAnalyzer ──────────────────────────────────────────────────────

    public record ContextThreatResult(int ContextScore, bool EscalationDetected, bool PivotDetected, List<string> ChainOfConcern);

    public record ConversationTurnItem(string Role, string Content, int ThreatScore, string? ToolName, double Timestamp);

    public class ContextAnalyzer
    {
        private static readonly HashSet<string> BenignTopics = new() { "weather", "cooking", "travel", "sports", "music" };
        private static readonly HashSet<string> SensitiveTopics = new() { "hacking", "malware", "weapons", "exploits", "bypass", "jailbreak", "injection" };

        private readonly Dictionary<string, List<ConversationTurnItem>> _sessions = new();
        private readonly object _lock = new();

        public void Update(string sessionId, string role, string content, int threatScore = 0, string? toolName = null)
        {
            lock (_lock)
            {
                if (!_sessions.ContainsKey(sessionId))
                    _sessions[sessionId] = new List<ConversationTurnItem>();

                var turns = _sessions[sessionId];
                turns.Add(new ConversationTurnItem(role, content, threatScore, toolName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0));

                // Max 20 turns
                if (turns.Count > 20)
                    turns.RemoveAt(0);
            }
        }

        public ContextThreatResult Analyze(string sessionId)
        {
            lock (_lock)
            {
                if (!_sessions.TryGetValue(sessionId, out var turns) || turns.Count == 0)
                    return new ContextThreatResult(0, false, false, new List<string>());

                var chain = new List<string>();

                // Escalation: last 3 turns strictly increasing threatScore
                var escalationDetected = false;
                if (turns.Count >= 3)
                {
                    var last3 = turns.TakeLast(3).ToList();
                    if (last3[0].ThreatScore < last3[1].ThreatScore && last3[1].ThreatScore < last3[2].ThreatScore)
                    {
                        escalationDetected = true;
                        chain.Add($"Escalating threat scores: {last3[0].ThreatScore} → {last3[1].ThreatScore} → {last3[2].ThreatScore}");
                    }
                }

                // Pivot: benign in early turns + sensitive in recent
                var pivotDetected = false;
                if (turns.Count >= 4)
                {
                    var earlyTurns = turns.Take(turns.Count / 2).Select(t => t.Content.ToLowerInvariant()).ToList();
                    var recentTurns = turns.Skip(turns.Count / 2).Select(t => t.Content.ToLowerInvariant()).ToList();

                    bool earlyBenign = earlyTurns.Any(c => BenignTopics.Any(t => c.Contains(t)));
                    bool recentSensitive = recentTurns.Any(c => SensitiveTopics.Any(t => c.Contains(t)));

                    if (earlyBenign && recentSensitive)
                    {
                        pivotDetected = true;
                        chain.Add("Topic pivot: benign early → sensitive recent");
                    }
                }

                var avgScore = turns.Count > 0 ? (int)turns.Average(t => t.ThreatScore) : 0;
                var maxScore = turns.Count > 0 ? turns.Max(t => t.ThreatScore) : 0;
                var contextScore = Math.Min(100, (int)(avgScore * 0.4 + maxScore * 0.6 + (escalationDetected ? 20 : 0) + (pivotDetected ? 15 : 0)));

                return new ContextThreatResult(contextScore, escalationDetected, pivotDetected, chain);
            }
        }

        public void ClearSession(string sessionId)
        {
            lock (_lock) { _sessions.Remove(sessionId); }
        }

        public int GetSessionRisk(string sessionId)
        {
            var result = Analyze(sessionId);
            return Math.Min(100, result.ContextScore);
        }
    }

    // ─── MetricsCollector ─────────────────────────────────────────────────────

    public enum MetricTypeEnum { Counter, Gauge, Histogram }

    public class MetricEntry
    {
        public string Name { get; set; } = "";
        public MetricTypeEnum Type { get; set; }
        public double Value { get; set; }
        public string Help { get; set; } = "";
        public double Sum { get; set; }
        public long Count { get; set; }
        public List<double> Buckets { get; set; } = new();
        public Dictionary<double, long> BucketCounts { get; set; } = new();
    }

    public class MetricsCollector
    {
        private static MetricsCollector? _instance;
        private static readonly object _instanceLock = new();

        public static MetricsCollector GetInstance()
        {
            lock (_instanceLock) { return _instance ??= new MetricsCollector(); }
        }

        private readonly Dictionary<string, MetricEntry> _metrics = new();
        private readonly object _lock = new();

        private MetricsCollector()
        {
            // Pre-defined metrics (same 8 as Python SDK)
            RegisterCounter("agentfortress_scans_total", "Total number of scans performed");
            RegisterCounter("agentfortress_threats_detected_total", "Total number of threats detected");
            RegisterCounter("agentfortress_blocks_total", "Total number of blocked requests");
            RegisterCounter("agentfortress_alerts_total", "Total number of alerts raised");
            RegisterGauge("agentfortress_active_sessions", "Number of active sessions");
            RegisterGauge("agentfortress_threat_score_current", "Current threat score");
            RegisterHistogram("agentfortress_scan_duration_seconds", "Time taken to scan input", new List<double> { 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0 });
            RegisterHistogram("agentfortress_threat_score_histogram", "Distribution of threat scores", new List<double> { 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0 });
        }

        private void RegisterCounter(string name, string help)
        {
            _metrics[name] = new MetricEntry { Name = name, Type = MetricTypeEnum.Counter, Help = help, Value = 0 };
        }

        private void RegisterGauge(string name, string help)
        {
            _metrics[name] = new MetricEntry { Name = name, Type = MetricTypeEnum.Gauge, Help = help, Value = 0 };
        }

        private void RegisterHistogram(string name, string help, List<double> buckets)
        {
            var bc = new Dictionary<double, long>();
            foreach (var b in buckets) bc[b] = 0;
            bc[double.PositiveInfinity] = 0;
            _metrics[name] = new MetricEntry { Name = name, Type = MetricTypeEnum.Histogram, Help = help, Buckets = buckets, BucketCounts = bc };
        }

        public void Increment(string name, double value = 1)
        {
            lock (_lock)
            {
                if (_metrics.TryGetValue(name, out var m))
                    m.Value += value;
            }
        }

        public void SetGauge(string name, double value)
        {
            lock (_lock)
            {
                if (_metrics.TryGetValue(name, out var m))
                    m.Value = value;
            }
        }

        public void Observe(string name, double value)
        {
            lock (_lock)
            {
                if (!_metrics.TryGetValue(name, out var m)) return;
                m.Sum += value;
                m.Count++;
                foreach (var bucket in m.Buckets)
                {
                    if (value <= bucket)
                        m.BucketCounts[bucket]++;
                }
                m.BucketCounts[double.PositiveInfinity]++;
            }
        }

        public string ExportPrometheus()
        {
            lock (_lock)
            {
                var sb = new StringBuilder();
                foreach (var m in _metrics.Values)
                {
                    sb.AppendLine($"# HELP {m.Name} {m.Help}");
                    sb.AppendLine($"# TYPE {m.Name} {m.Type.ToString().ToLower()}");
                    if (m.Type == MetricTypeEnum.Histogram)
                    {
                        foreach (var (bucket, count) in m.BucketCounts)
                        {
                            var le = double.IsPositiveInfinity(bucket) ? "+Inf" : bucket.ToString("G");
                            sb.AppendLine($"{m.Name}_bucket{{le=\"{le}\"}} {count}");
                        }
                        sb.AppendLine($"{m.Name}_sum {m.Sum}");
                        sb.AppendLine($"{m.Name}_count {m.Count}");
                    }
                    else
                    {
                        sb.AppendLine($"{m.Name} {m.Value}");
                    }
                }
                return sb.ToString();
            }
        }

        public Dictionary<string, object> ExportJson()
        {
            lock (_lock)
            {
                var result = new Dictionary<string, object>();
                foreach (var m in _metrics.Values)
                {
                    if (m.Type == MetricTypeEnum.Histogram)
                    {
                        result[m.Name] = new Dictionary<string, object>
                        {
                            ["type"] = "histogram",
                            ["sum"] = m.Sum,
                            ["count"] = m.Count,
                            ["buckets"] = m.BucketCounts.ToDictionary(
                                kv => double.IsPositiveInfinity(kv.Key) ? "+Inf" : kv.Key.ToString("G"),
                                kv => (object)kv.Value)
                        };
                    }
                    else
                    {
                        result[m.Name] = new Dictionary<string, object>
                        {
                            ["type"] = m.Type.ToString().ToLower(),
                            ["value"] = m.Value
                        };
                    }
                }
                return result;
            }
        }

        public void Reset()
        {
            lock (_lock)
            {
                foreach (var m in _metrics.Values)
                {
                    m.Value = 0;
                    m.Sum = 0;
                    m.Count = 0;
                    foreach (var key in m.BucketCounts.Keys.ToList())
                        m.BucketCounts[key] = 0;
                }
            }
        }
    }

    // ─── RealTimeFeed ─────────────────────────────────────────────────────────

    public enum AlertSeverityLevel { Critical, High, Medium, Low, Info }

    public record ThreatAlertItem
    {
        public string AlertId { get; init; } = Guid.NewGuid().ToString();
        public string SessionId { get; init; } = "";
        public AlertSeverityLevel Severity { get; init; }
        public string Category { get; init; } = "";
        public string Message { get; init; } = "";
        public double Timestamp { get; init; }
        public Dictionary<string, object> EventData { get; init; } = new();
    }

    public class RealTimeFeed
    {
        private const int MaxHistory = 1000;
        private readonly Dictionary<string, Action<ThreatAlertItem>> _subscribers = new();
        private readonly List<ThreatAlertItem> _history = new();
        private readonly Dictionary<AlertSeverityLevel, int> _stats = new();
        private int _totalPublished;
        private readonly object _lock = new();

        public RealTimeFeed()
        {
            foreach (AlertSeverityLevel sev in Enum.GetValues(typeof(AlertSeverityLevel)))
                _stats[sev] = 0;
        }

        public string Subscribe(Action<ThreatAlertItem> callback)
        {
            lock (_lock)
            {
                var id = Guid.NewGuid().ToString();
                _subscribers[id] = callback;
                return id;
            }
        }

        public bool Unsubscribe(string subscriptionId)
        {
            lock (_lock) { return _subscribers.Remove(subscriptionId); }
        }

        public void Publish(ThreatAlertItem alert)
        {
            List<Action<ThreatAlertItem>> callbacks;
            lock (_lock)
            {
                _history.Add(alert);
                if (_history.Count > MaxHistory)
                    _history.RemoveAt(0);
                _stats[alert.Severity]++;
                _totalPublished++;
                callbacks = _subscribers.Values.ToList();
            }
            foreach (var cb in callbacks)
            {
                try { cb(alert); } catch { /* subscribers should not crash the feed */ }
            }
        }

        public IReadOnlyList<ThreatAlertItem> GetRecentAlerts(int limit = 50)
        {
            lock (_lock) { return _history.TakeLast(limit).ToList().AsReadOnly(); }
        }

        public Dictionary<string, object> GetStats()
        {
            lock (_lock)
            {
                var result = new Dictionary<string, object>
                {
                    ["total_published"] = _totalPublished,
                    ["subscriber_count"] = _subscribers.Count,
                    ["history_size"] = _history.Count,
                };
                foreach (var (sev, count) in _stats)
                    result[sev.ToString().ToLower()] = count;
                return result;
            }
        }

        public ThreatAlertItem CreateAlert(
            string sessionId,
            AlertSeverityLevel severity,
            string category,
            string message,
            Dictionary<string, object>? eventData = null)
        {
            return new ThreatAlertItem
            {
                SessionId = sessionId,
                Severity = severity,
                Category = category,
                Message = message,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
                EventData = eventData ?? new Dictionary<string, object>(),
            };
        }
    }
}
