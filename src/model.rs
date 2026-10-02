use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL_DESC: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" | "moderate" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            other => bail!("unknown severity '{other}'"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// A deterministic rule.
    Rule,
    /// The LLM review of the residue. Advisory only.
    Llm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule id, e.g. "nginx.secret_exposed". LLM findings use "llm".
    pub rule: String,
    pub severity: Severity,
    pub origin: Origin,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// Sample log lines / facts; capped when the finding is built.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// How many log events this finding aggregates.
    pub count: u64,
    /// Stable key for repeat suppression (same problem on consecutive days).
    pub fingerprint: String,
    /// Set when an identical alert was already pushed recently.
    #[serde(default)]
    pub repeat: bool,
}

pub const MAX_EVIDENCE: usize = 8;

impl Finding {
    pub fn new(rule: &str, severity: Severity, title: impl Into<String>, key: &str) -> Self {
        Self {
            rule: rule.to_string(),
            severity,
            origin: Origin::Rule,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
            count: 1,
            fingerprint: format!("{rule}:{key}"),
            repeat: false,
        }
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }

    pub fn count(mut self, n: u64) -> Self {
        self.count = n;
        self
    }

    pub fn evidence<I, S>(mut self, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for l in lines.into_iter().take(MAX_EVIDENCE.saturating_sub(self.evidence.len())) {
            self.evidence.push(truncate(&l.into(), 400));
        }
        self
    }
}

/// Counters that are reported but never alerted on.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub journal_entries: u64,
    pub nginx_requests: u64,
    pub nginx_unparsed: u64,
    /// Events no rule matched (what the LLM skills look at).
    pub residue_events: u64,
    /// Events dropped by `ignore` rules.
    pub ignored_events: u64,
    /// One entry per `stat` rule that matched anything.
    pub rules: Vec<StatEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatEntry {
    pub rule: String,
    pub title: String,
    pub total: u64,
    pub groups: u64,
    /// Top groups, "key (count)".
    pub top: Vec<String>,
}

/// Result of one LLM skill run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmVerdict {
    pub skill: String,
    pub provider: String,
    pub model: String,
    pub assessment: String,
    pub summary: String,
    pub input_chars: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub host: String,
    pub version: String,
    pub since: DateTime<Local>,
    pub until: DateTime<Local>,
    pub findings: Vec<Finding>,
    pub stats: Stats,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm: Vec<LlmVerdict>,
    /// Non-fatal problems (unreadable file, LLM failure, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl Report {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn count_at(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}
