//! LLM client setup (opskit::llm) and verdict parsing.

use anyhow::{Context, Result};
use opskit::llm::ClientConfig;
use serde::Deserialize;
use serde_json::Value;

use crate::config::Llm;

pub use opskit::llm::{Client, Reply};

pub fn client(cfg: &Llm) -> Result<Client> {
    Ok(Client::new(ClientConfig {
        base_url: cfg.base_url.clone(),
        api_key: cfg.api_key()?,
        timeout_secs: cfg.timeout_secs,
        max_tokens: cfg.max_tokens,
        json_mode: cfg.json_mode,
        extra_body: serde_json::to_value(&cfg.extra_body).context("llm.extra_body")?,
        user_agent: concat!("logscan/", env!("CARGO_PKG_VERSION")).into(),
    }))
}

// ---------------------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Verdict {
    #[serde(default)]
    pub assessment: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<LlmFinding>,
}

#[derive(Debug, Deserialize)]
pub struct LlmFinding {
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, deserialize_with = "strings")]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub recommendation: String,
}

/// Accepts a string or an array of strings.
fn strings<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(s) => vec![s],
        Value::Array(a) => a.into_iter().map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).collect(),
        Value::Null => Vec::new(),
        other => vec![other.to_string()],
    })
}

pub const ASSESSMENTS: &[&str] = &["clean", "suspicious", "compromise_suspected"];

/// Parses the model's answer; tolerates code fences and text around the JSON object.
pub fn parse_verdict(content: &str) -> Result<Verdict> {
    let json = opskit::llm::json_object(content)?;
    let mut v: Verdict = serde_json::from_str(json).context("answer JSON doesn't match the schema")?;
    v.assessment = v.assessment.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    if !ASSESSMENTS.contains(&v.assessment.as_str()) {
        v.assessment = format!("unknown ({})", v.assessment);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fenced_and_loose_json() {
        let v = parse_verdict(
            "<think>hmm</think>```json\n{\"assessment\":\"Suspicious\",\"summary\":\"x\",\"findings\":[{\"severity\":\"high\",\"title\":\"t\",\"evidence\":\"one line\"}]}\n```",
        )
        .unwrap();
        assert_eq!(v.assessment, "suspicious");
        assert_eq!(v.findings[0].evidence, vec!["one line"]);
        assert!(parse_verdict("no json here").is_err());
        assert!(parse_verdict("{\"assessment\": 5}").is_err());
        assert_eq!(parse_verdict("{}").unwrap().assessment, "unknown ()");
    }
}
