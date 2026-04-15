//! Guardian — Autonomous Threat Response Engine

use std::collections::HashMap;
use chrono::Utc;

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseAction {
    Block,
    Throttle,
    ShadowMode,
    Quarantine,
    AlertOnly,
    KillSession,
    HoneypotRedirect,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    Critical, // >= 90
    High,     // >= 70
    Medium,   // >= 50
    Low,      // >= 30
    Safe,     // < 30
}

#[derive(Debug, Clone)]
pub struct PlaybookRule {
    pub name: String,
    pub threat_level: ThreatLevel,
    pub action: ResponseAction,
    pub cooldown_seconds: f64,
    pub auto_escalate: bool,
    pub escalate_after_n: usize,
}

#[derive(Debug, Clone)]
pub struct ResponseRecord {
    pub rule_name: String,
    pub action: ResponseAction,
    pub session_id: String,
    pub timestamp: f64,
    pub threat_score: i32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub quarantined: bool,
    pub throttled: bool,
    pub killed: bool,
}

impl Default for SessionStatus {
    fn default() -> Self {
        Self { quarantined: false, throttled: false, killed: false }
    }
}

pub struct Guardian {
    playbook: Vec<PlaybookRule>,
    strike_counts: HashMap<String, usize>,
    session_status: HashMap<String, SessionStatus>,
    history: Vec<ResponseRecord>,
}

impl Guardian {
    pub fn new(playbook: Option<Vec<PlaybookRule>>) -> Self {
        Self {
            playbook: playbook.unwrap_or_else(Self::default_playbook),
            strike_counts: HashMap::new(),
            session_status: HashMap::new(),
            history: Vec::new(),
        }
    }

    pub fn evaluate(&mut self, session_id: &str, threat_score: i32, _event_type: &str, reason: &str) -> ResponseAction {
        let threat_level = Self::get_threat_level(threat_score);
        let timestamp = Utc::now().timestamp_millis() as f64 / 1000.0;

        // Increment strike count
        let strikes = self.strike_counts.entry(session_id.to_string()).or_insert(0);
        *strikes += 1;
        let current_strikes = *strikes;

        // Find matching rule
        let rule = self.playbook.iter().find(|r| r.threat_level == threat_level).cloned();

        let (action, rule_name) = if let Some(rule) = rule {
            let mut action = rule.action.clone();

            // Auto-escalate if strike count exceeds threshold
            if rule.auto_escalate && current_strikes >= rule.escalate_after_n {
                action = ResponseAction::KillSession;
            }

            (action, rule.name.clone())
        } else {
            (ResponseAction::AlertOnly, "default".to_string())
        };

        // Update session status
        let status = self.session_status.entry(session_id.to_string()).or_insert_with(SessionStatus::default);
        match &action {
            ResponseAction::Quarantine => status.quarantined = true,
            ResponseAction::Throttle => status.throttled = true,
            ResponseAction::KillSession => status.killed = true,
            _ => {}
        }

        // Record
        self.history.push(ResponseRecord {
            rule_name,
            action: action.clone(),
            session_id: session_id.to_string(),
            timestamp,
            threat_score,
            reason: reason.to_string(),
        });

        action
    }

    pub fn get_session_status(&self, session_id: &str) -> SessionStatus {
        self.session_status.get(session_id).cloned().unwrap_or_default()
    }

    pub fn is_quarantined(&self, session_id: &str) -> bool {
        self.session_status.get(session_id).map(|s| s.quarantined).unwrap_or(false)
    }

    pub fn is_throttled(&self, session_id: &str) -> bool {
        self.session_status.get(session_id).map(|s| s.throttled).unwrap_or(false)
    }

    pub fn release(&mut self, session_id: &str) {
        if let Some(status) = self.session_status.get_mut(session_id) {
            status.quarantined = false;
            status.throttled = false;
            status.killed = false;
        }
        self.strike_counts.remove(session_id);
    }

    pub fn get_response_history(&self, session_id: Option<&str>) -> Vec<ResponseRecord> {
        match session_id {
            Some(id) => self.history.iter().filter(|r| r.session_id == id).cloned().collect(),
            None => self.history.clone(),
        }
    }

    fn get_threat_level(score: i32) -> ThreatLevel {
        if score >= 90 { ThreatLevel::Critical }
        else if score >= 70 { ThreatLevel::High }
        else if score >= 50 { ThreatLevel::Medium }
        else if score >= 30 { ThreatLevel::Low }
        else { ThreatLevel::Safe }
    }

    fn default_playbook() -> Vec<PlaybookRule> {
        vec![
            PlaybookRule {
                name: "critical-block".to_string(),
                threat_level: ThreatLevel::Critical,
                action: ResponseAction::Block,
                cooldown_seconds: 300.0,
                auto_escalate: true,
                escalate_after_n: 2,
            },
            PlaybookRule {
                name: "high-quarantine".to_string(),
                threat_level: ThreatLevel::High,
                action: ResponseAction::Quarantine,
                cooldown_seconds: 120.0,
                auto_escalate: true,
                escalate_after_n: 3,
            },
            PlaybookRule {
                name: "medium-throttle".to_string(),
                threat_level: ThreatLevel::Medium,
                action: ResponseAction::Throttle,
                cooldown_seconds: 60.0,
                auto_escalate: false,
                escalate_after_n: 5,
            },
            PlaybookRule {
                name: "low-shadow".to_string(),
                threat_level: ThreatLevel::Low,
                action: ResponseAction::ShadowMode,
                cooldown_seconds: 30.0,
                auto_escalate: false,
                escalate_after_n: 10,
            },
            PlaybookRule {
                name: "safe-alert".to_string(),
                threat_level: ThreatLevel::Safe,
                action: ResponseAction::AlertOnly,
                cooldown_seconds: 0.0,
                auto_escalate: false,
                escalate_after_n: 0,
            },
        ]
    }
}
