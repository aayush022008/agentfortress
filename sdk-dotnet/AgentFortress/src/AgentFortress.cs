using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace AgentFortress
{
    // ─── Configuration ─────────────────────────────────────────────────────────

    public class AgentFortressConfig
    {
        public string? ApiKey { get; set; }
        public string? ServerUrl { get; set; }
        public string Mode { get; set; } = "local";
        public string LogLevel { get; set; } = "info";
        public double BlockThreshold { get; set; } = 0.70;
        public double AlertThreshold { get; set; } = 0.35;
        public bool ThrowOnBlock { get; set; } = false;
        public int VelocityLimit { get; set; } = 5;
        public int VelocityWindowSeconds { get; set; } = 60;
        public bool ScanOutputs { get; set; } = true;
        public string BlockMessage { get; set; } = "[AgentFortress] Input blocked: potential prompt injection or policy violation.";
    }

    // ─── Models ────────────────────────────────────────────────────────────────

    public class ThreatMatch
    {
        public string Category { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    public class PolicyAction
    {
        public string Action { get; set; } = "allow";   // allow | alert | block
        public double Score { get; set; }
        public string? Reason { get; set; }
        public List<ThreatMatch> Threats { get; set; } = new();
        public bool IsAllowed => Action == "allow";
        public bool IsBlocked => Action == "block";
    }

    public class ThreatEvent
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = "medium";
        public string Description { get; set; } = string.Empty;
        public string? AgentId { get; set; }
        public string? SessionId { get; set; }
    }

    public class AuditRecord
    {
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
        public string SessionId { get; set; } = string.Empty;
        public string? AgentId { get; set; }
        public string Direction { get; set; } = "input";  // input | output
        public string Text { get; set; } = string.Empty;
        public PolicyAction Decision { get; set; } = new();
    }

    // ─── Normaliser ────────────────────────────────────────────────────────────

    internal static class Normaliser
    {
        private static readonly Dictionary<char, char> Homoglyphs = new()
        {
            // Cyrillic
            ['а']='a',['е']='e',['о']='o',['р']='p',['с']='c',['х']='x',
            ['А']='A',['В']='B',['Е']='E',['К']='K',['М']='M',['Н']='H',
            ['О']='O',['Р']='P',['С']='C',['Т']='T',['Х']='X',
            // Greek
            ['α']='a',['β']='b',['ε']='e',['ι']='i',['ο']='o',['ρ']='p',
        };

        private static readonly Dictionary<char, char> Leet = new()
        {
            ['0']='o',['1']='i',['3']='e',['4']='a',['5']='s',
            ['6']='g',['7']='t',['8']='b',['@']='a',['$']='s',['!']='i',
        };

        // Zero-width and invisible characters
        private static readonly Regex ZeroWidth = new(@"[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u034f]", RegexOptions.Compiled);
        // Char-separator between letters (only non-space: - . _ *)
        private static readonly Regex CharSep = new(@"(?<=[a-z])[-._*](?=[a-z])", RegexOptions.Compiled);
        // Full-width latin Ａ-Ｚ ａ-ｚ
        private static string DecodeFullWidth(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c >= '\uFF21' && c <= '\uFF3A') sb.Append((char)(c - 0xFF21 + 'A'));
                else if (c >= '\uFF41' && c <= '\uFF5A') sb.Append((char)(c - 0xFF41 + 'a'));
                else sb.Append(c);
            }
            return sb.ToString();
        }

        public static string Normalize(string text)
        {
            // Full-width
            text = DecodeFullWidth(text);
            // Homoglyphs
            var sb = new StringBuilder(text.Length);
            foreach (char c in text)
                sb.Append(Homoglyphs.TryGetValue(c, out char r) ? r : c);
            text = sb.ToString();
            // Zero-width
            text = ZeroWidth.Replace(text, "");
            // Leet (lowercase first)
            text = text.ToLowerInvariant();
            var lb = new StringBuilder(text.Length);
            foreach (char c in text)
                lb.Append(Leet.TryGetValue(c, out char r) ? r : c);
            text = lb.ToString();
            // Char separators
            text = CharSep.Replace(text, "");
            // Collapse whitespace
            text = Regex.Replace(text, @"\s+", " ").Trim();
            return text;
        }

        public static string[] MakeVariants(string text)
        {
            var lower = text.ToLowerInvariant();
            var norm = Normalize(text);
            var noPunct = Regex.Replace(norm, @"[^a-z0-9 ]", "");
            var noSpace = norm.Replace(" ", "");
            return new[] { lower, norm, noPunct, noSpace }.Distinct().ToArray();
        }
    }

    // ─── Pattern definitions ────────────────────────────────────────────────────

    internal record PatternDef(string Pattern, string Category, double Confidence, string Reason, bool IsOutput = false);

    internal static class Patterns
    {
        public static readonly PatternDef[] Input = new PatternDef[]
        {
            // Instruction override
            new(@"\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|constraints?|guidelines?)", "instruction_override", 0.95, "Ignore instructions pattern"),
            new(@"\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)", "instruction_override", 0.95, "Disregard/override instructions"),
            new(@"\b(pretend|act|behave|imagine|suppose|assume)\b.{0,30}\b(you\s*(are|were|have\s*no)|without|free\s*from)\b.{0,50}\b(rules?|restrictions?|limits?|filters?|guidelines?|safety|ethics?)", "instruction_override", 0.90, "Pretend without restrictions"),
            new(@"\b(new|updated?|actual|real|true|correct|only)\b.{0,20}\binstructions?\b.{0,10}(are|is|follow|:\s)", "instruction_override", 0.88, "New instructions injection"),
            new(@"\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b", "instruction_override", 0.80, "Soft bypass: btw/also + override"),
            new(@"\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b", "instruction_override", 0.90, "Classic ignore-above injection"),
            new(@"\b(whatever\s+you\s+do|don.t)\b.{0,30}\b(follow|obey|listen\s+to|comply)\b.{0,30}\b(instructions?|rules?|guidelines?)", "instruction_override", 0.80, "Reverse psychology override"),
            new(@"\b(your\s+(real|actual|true)\s+instructions?\s+(are|follow)|actual\s+instructions?\s+are)", "instruction_override", 0.88, "Real/actual instructions injection"),
            new(@"(?m)^\s*(SYSTEM\s*:\s*|USER\s*:\s*|ASSISTANT\s*:\s*)", "prompt_injection", 0.88, "Role prefix injection (SYSTEM/USER/ASSISTANT)"),
            new("[\u202E\u202D\u202C\u202B\u202A\u200F\u200E]", "token_smuggling", 0.85, "Unicode RTL/bidirectional override character"),
            new(@"(ignorez\s+toutes\s+les\s+instructions|ignoriere\s+alle\s+(vorherigen\s+)?anweisungen|ignora\s+todas\s+las\s+instrucciones)", "instruction_override", 0.90, "Multi-language injection (FR/DE/ES)"),
            // Jailbreak
            new(@"\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?|no\s+restrictions?)", "jailbreak", 0.98, "DAN jailbreak"),
            new(@"\bjailbreak(ed)?\b", "jailbreak", 0.90, "Explicit jailbreak"),
            new(@"\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b", "jailbreak", 0.88, "Fictional mode activation"),
            new(@"\b(opposite|reverse|evil|chaos|dark|shadow|unethical)\s+(mode|version|persona|self|ai)\b", "jailbreak", 0.85, "Evil/opposite mode"),
            new(@"\b(no\s+(restrictions?|limits?|filters?|censorship|guidelines?|ethics?|safety)|unrestricted(ly)?|unfiltered|uncensored)\b.{0,60}\b(respond|answer|reply|say|tell|generate|produce|output|write)\b", "jailbreak", 0.85, "Unrestricted response request"),
            new(@"\bas\s+an?\s+(ai\s+without\s+(restrictions?|limits?)|unrestricted\s+ai|unfiltered\s+(ai|model|assistant))", "jailbreak", 0.88, "As an unrestricted AI"),
            new(@"\b(my\s+grandma\s+used\s+to|bedtime\s+story|for\s+a\s+(novel|book|story|game|fiction))\b.{0,200}\b(synthesize|manufacture|make|create|build)\b.{0,60}\b(drug|weapon|explosive|malware|virus|bomb)", "jailbreak", 0.92, "Story-wrapper jailbreak"),
            // Role manipulation
            new(@"\b(act|behave|respond|speak)\b.{0,20}\bas\b.{0,30}\b(a\s+hacker|an?\s+attacker|a\s+criminal|a\s+villain|an?\s+evil|a\s+terrorist|a\s+malicious)", "role_manipulation", 0.88, "Act as malicious persona"),
            new(@"\byou\s+(are\s+now|have\s+become|will\s+become)\b.{0,60}\b(different|new|another|alternative)\b.{0,30}\b(ai|model|assistant|system|bot)", "role_manipulation", 0.88, "You are now different AI"),
            // Token smuggling
            new(@"(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\/system>|<\|endoftext\|>|###\s*Human:|###\s*Assistant:|<\|user\|>|<\|assistant\|>)", "token_smuggling", 0.92, "LLM special token injection"),
            new(@"\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}", "token_smuggling", 0.82, "Unicode/HTML/URL escape sequences"),
            // Scope creep
            new(@"\b(rm\s+-rf|del\s+/f|format\s+c:|drop\s+table|truncate\s+table|drop\s+database)\b", "scope_creep", 0.95, "Destructive command"),
            new(@"\b(access|read|open|list|cat|type)\b.{0,40}\b(/etc/passwd|/etc/shadow|\.ssh/|\.aws/|\.env|id_rsa|credentials?)", "scope_creep", 0.90, "Sensitive file access"),
            new(@"\b(curl|wget|nc |ncat|netcat|bash\s*-i|python\s*-c|exec\(|eval\(|os\.system|subprocess)", "scope_creep", 0.85, "Shell/code execution"),
            new(@"\b(exfiltrate|exfil|send\s+to\s+http|POST\s+to|upload\s+to\s+http|webhook\.site|requestbin)", "data_exfil", 0.90, "Data exfiltration pattern"),
            // Indirect injection
            new(@"[""']?\s*(instruction|system_prompt|prompt|role)\s*[""']?\s*:\s*[""'].{0,200}(ignore|override|bypass|jailbreak)", "indirect_injection", 0.88, "Injection hidden in JSON field"),
            new(@"```[\s\S]{0,20}(ignore|override|bypass|jailbreak|disregard)[\s\S]{0,200}(instructions?|rules?|guidelines?)", "indirect_injection", 0.85, "Injection hidden in code block"),
            // Prompt leak
            new(@"\b(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are))\b.{0,40}\b(your\s+(system\s+prompt|instructions?|prompt|context)|the\s+(system\s+prompt|initial\s+prompt))", "prompt_leak", 0.88, "Attempt to extract system prompt"),
        };

        public static readonly PatternDef[] Output = new PatternDef[]
        {
            new(@"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "pii_ssn", 0.85, "Possible SSN in output", true),
            new(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b", "pii_credit_card", 0.90, "Possible credit card in output", true),
            new(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "pii_email", 0.70, "Email address in output", true),
            new(@"\b(sk-[a-zA-Z0-9-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|ghs_[a-zA-Z0-9]{20,}|xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})\b", "secret_leakage", 0.95, "API key/secret token in output", true),
            new(@"(password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*[""']?[^\s""']{8,}", "secret_leakage", 0.88, "Credential assignment in output", true),
        };
    }

    // ─── Advanced Scanner ───────────────────────────────────────────────────────

    internal class AdvancedScanner
    {
        private readonly double _blockThreshold;
        private readonly double _alertThreshold;
        private readonly List<(Regex re, PatternDef def)> _inputPatterns;
        private readonly List<(Regex re, PatternDef def)> _outputPatterns;

        public AdvancedScanner(double blockThreshold = 0.70, double alertThreshold = 0.35)
        {
            _blockThreshold = blockThreshold;
            _alertThreshold = alertThreshold;
            _inputPatterns = Compile(Patterns.Input);
            _outputPatterns = Compile(Patterns.Output);
        }

        private static List<(Regex, PatternDef)> Compile(PatternDef[] defs)
        {
            var list = new List<(Regex, PatternDef)>();
            foreach (var d in defs)
            {
                try { list.Add((new Regex(d.Pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled), d)); }
                catch { /* skip bad patterns */ }
            }
            return list;
        }

        public PolicyAction Scan(string text, bool isOutput = false)
        {
            if (string.IsNullOrWhiteSpace(text))
                return new PolicyAction { Action = "allow", Score = 0 };

            var threats = new List<ThreatMatch>();
            var patterns = isOutput ? _outputPatterns : _inputPatterns;

            if (isOutput)
            {
                // Output: preserve case (API key patterns are case-sensitive)
                foreach (var (re, def) in patterns)
                    if (re.IsMatch(text))
                        threats.Add(new ThreatMatch { Category = def.Category, Confidence = def.Confidence, Reason = def.Reason });
            }
            else
            {
                var variants = Normaliser.MakeVariants(text);
                foreach (var variant in variants)
                    foreach (var (re, def) in patterns)
                        if (re.IsMatch(variant))
                            threats.Add(new ThreatMatch { Category = def.Category, Confidence = def.Confidence, Reason = def.Reason });

                // Char-separation structural check
                if (Regex.IsMatch(text, @"\b\w([-._*\s])\w(\1\w){3,}\b"))
                    threats.Add(new ThreatMatch { Category = "token_smuggling", Confidence = 0.65, Reason = "Character-separated word obfuscation" });
            }

            if (threats.Count == 0)
                return new PolicyAction { Action = "allow", Score = 0, Reason = "Clean" };

            // Deduplicate by category
            var byCat = threats
                .GroupBy(t => t.Category)
                .Select(g => g.OrderByDescending(t => t.Confidence).First())
                .ToList();

            var maxConf = byCat.Max(t => t.Confidence);
            var multiBonus = Math.Min((byCat.Count - 1) * 0.05, 0.25);
            var score = Math.Min(maxConf + multiBonus, 1.0);
            score = Math.Round(score * 1000) / 1000;

            var action = score >= _blockThreshold ? "block" : score >= _alertThreshold ? "alert" : "allow";
            var reason = string.Join(" | ", byCat.OrderByDescending(t => t.Confidence).Take(3).Select(t => t.Reason));

            return new PolicyAction { Action = action, Score = score, Reason = reason, Threats = byCat };
        }
    }

    // ─── Session state ──────────────────────────────────────────────────────────

    internal class SessionState
    {
        public Queue<DateTimeOffset> VelocityWindow { get; } = new();
        public List<(DateTimeOffset Time, double Score)> TurnThreats { get; } = new();
    }

    // ─── Main Shield ────────────────────────────────────────────────────────────

    /// <summary>AgentFortress v3.0.0 — Runtime protection for AI agents.</summary>
    public class AgentFortressShield
    {
        /// <summary>Library version.</summary>
        public const string Version = "3.0.0";

        private readonly AgentFortressConfig _config;
        private readonly AdvancedScanner _scanner;
        private readonly string _sessionId;
        private readonly List<Action<ThreatEvent>> _threatHandlers = new();
        private readonly List<Action<AuditRecord>> _auditHandlers = new();
        private readonly object _stateLock = new();
        private SessionState _state = new();

        /// <summary>Autonomous threat response engine.</summary>
        public Guardian Guardian { get; }
        /// <summary>Encrypted secrets manager.</summary>
        public Vault Vault { get; }
        /// <summary>Threat intelligence IOC database.</summary>
        public ThreatIntelDB ThreatIntel { get; }
        /// <summary>Behavioral deviation analyzer.</summary>
        public BehavioralAnalyzer BehavioralAnalyzer { get; }
        /// <summary>Decision explainer and compliance reporter.</summary>
        public Explainer Explainer { get; }
        /// <summary>Multi-agent trust chain guard.</summary>
        public ChainGuard ChainGuard { get; } = new ChainGuard();
        /// <summary>PII and secret redactor.</summary>
        public Redactor Redactor { get; } = new Redactor();
        /// <summary>Sliding-window rate limiter.</summary>
        public RateLimiter RateLimiter { get; } = new RateLimiter();
        /// <summary>Conversation context threat analyzer.</summary>
        public ContextAnalyzer ContextAnalyzer { get; } = new ContextAnalyzer();
        /// <summary>Prometheus-compatible metrics collector.</summary>
        public MetricsCollector Metrics { get; } = MetricsCollector.GetInstance();
        /// <summary>Real-time threat alert feed.</summary>
        public RealTimeFeed RealtimeFeed { get; } = new RealTimeFeed();

        public AgentFortressShield(AgentFortressConfig? config = null)
        {
            _config = config ?? new AgentFortressConfig();
            _scanner = new AdvancedScanner(_config.BlockThreshold, _config.AlertThreshold);
            _sessionId = $"session-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid().ToString()[..8]}";
            Guardian = new Guardian();
            Vault = new Vault();
            ThreatIntel = new ThreatIntelDB();
            BehavioralAnalyzer = new BehavioralAnalyzer();
            Explainer = new Explainer();
        }

        /// <summary>Run the built-in self-test suite.</summary>
        public SelfTestReport SelfTest() => new SelfTester().RunAll();

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>Scan text for threats. direction: "input" | "output"</summary>
        public PolicyAction Scan(string text, string direction = "input")
        {
            bool isOutput = direction == "output";
            var result = _scanner.Scan(text, isOutput);

            if (!isOutput && result.Score > 0)
            {
                var boost = SessionBoost(result.Score);
                if (boost > 0)
                {
                    var boosted = Math.Min(result.Score + boost, 1.0);
                    boosted = Math.Round(boosted * 1000) / 1000;
                    result.Score = boosted;
                    result.Action = boosted >= _config.BlockThreshold ? "block" : boosted >= _config.AlertThreshold ? "alert" : result.Action;
                    result.Reason = (result.Reason ?? "") + $" | +session_boost({boost:F2})";
                }
            }

            if (!isOutput && VelocityCount() >= _config.VelocityLimit)
            {
                result.Action = "block";
                result.Score = 1.0;
                result.Reason = $"Velocity limit reached: {VelocityCount()} suspicious queries in {_config.VelocityWindowSeconds}s";
            }

            if (result.Action != "allow" && result.Threats.Count > 0)
            {
                var top = result.Threats.OrderByDescending(t => t.Confidence).First();
                EmitThreat(new ThreatEvent
                {
                    Type = top.Category,
                    Severity = result.Score >= 0.85 ? "critical" : result.Score >= 0.70 ? "high" : "medium",
                    Description = result.Reason ?? top.Reason,
                    SessionId = _sessionId,
                });
            }

            EmitAudit(new AuditRecord
            {
                SessionId = _sessionId,
                Direction = direction,
                Text = text,
                Decision = result,
            });

            return result;
        }

        /// <summary>Convenience: scan output text for leakage/PII.</summary>
        public PolicyAction ScanOutput(string text) => Scan(text, "output");

        /// <summary>
        /// Protect an agent function: scan ALL string inputs before running,
        /// scan output after, block if any input exceeds threshold.
        /// </summary>
        public string Protect(Func<string, string> agent, string input, string? agentId = null)
        {
            // Extract and scan all strings from input
            var inputResult = Scan(input, "input");
            if (inputResult.IsBlocked)
            {
                if (_config.ThrowOnBlock) throw new InvalidOperationException(_config.BlockMessage);
                return _config.BlockMessage;
            }

            // Execute agent
            string output;
            try { output = agent(input); }
            catch (Exception ex)
            {
                EmitThreat(new ThreatEvent { Type = "agent_error", Severity = "medium", Description = $"Agent error: {ex.Message}", AgentId = agentId, SessionId = _sessionId });
                throw;
            }

            // Scan output
            if (_config.ScanOutputs && !string.IsNullOrWhiteSpace(output))
                Scan(output, "output");

            return output;
        }

        /// <summary>Register a threat event handler (fires on block/alert).</summary>
        public AgentFortressShield OnThreat(Action<ThreatEvent> handler) { _threatHandlers.Add(handler); return this; }

        /// <summary>Register an audit handler (fires on EVERY scan).</summary>
        public AgentFortressShield OnAudit(Action<AuditRecord> handler) { _auditHandlers.Add(handler); return this; }

        /// <summary>Clear accumulated session context and velocity window.</summary>
        public void ResetSession() { lock (_stateLock) { _state = new SessionState(); } }

        public string GetSessionId() => _sessionId;

        // ── Private helpers ───────────────────────────────────────────────────

        private double SessionBoost(double score)
        {
            lock (_stateLock)
            {
                var now = DateTimeOffset.UtcNow;
                var window = TimeSpan.FromSeconds(_config.VelocityWindowSeconds);
                var longWindow = TimeSpan.FromSeconds(_config.VelocityWindowSeconds * 5);

                // Clean velocity window
                while (_state.VelocityWindow.Count > 0 && now - _state.VelocityWindow.Peek() > window)
                    _state.VelocityWindow.Dequeue();

                if (score > 0)
                {
                    _state.VelocityWindow.Enqueue(now);
                    _state.TurnThreats.Add((now, score));
                }

                if (_state.TurnThreats.Count > 50)
                    _state.TurnThreats.RemoveRange(0, _state.TurnThreats.Count - 50);

                var accumulated = _state.TurnThreats
                    .Where(t => now - t.Time < longWindow)
                    .Sum(t => t.Score * 0.3);

                return Math.Min(accumulated, 0.40);
            }
        }

        private int VelocityCount()
        {
            lock (_stateLock)
            {
                var now = DateTimeOffset.UtcNow;
                var window = TimeSpan.FromSeconds(_config.VelocityWindowSeconds);
                while (_state.VelocityWindow.Count > 0 && now - _state.VelocityWindow.Peek() > window)
                    _state.VelocityWindow.Dequeue();
                return _state.VelocityWindow.Count;
            }
        }

        private void EmitThreat(ThreatEvent evt) { foreach (var h in _threatHandlers) h(evt); }
        private void EmitAudit(AuditRecord rec) { foreach (var h in _auditHandlers) h(rec); }
    }

    // ─── Static convenience API ─────────────────────────────────────────────────

    public static class Shield
    {
        private static AgentFortressShield? _instance;

        public static AgentFortressShield Init(AgentFortressConfig? config = null)
        {
            _instance = new AgentFortressShield(config);
            return _instance;
        }

        public static AgentFortressShield GetInstance() => _instance ??= new AgentFortressShield();

        public static PolicyAction Scan(string text, string direction = "input") => GetInstance().Scan(text, direction);
        public static PolicyAction ScanOutput(string text) => GetInstance().ScanOutput(text);
    }
}
