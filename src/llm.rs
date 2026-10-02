//! Minimal OpenAI-compatible chat client (Venice, DeepSeek, …) and verdict parsing.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Llm;

pub struct Client {
    agent: ureq::Agent,
    base: String,
    key: String,
    max_tokens: u32,
    json_mode: bool,
    extra: Value,
}

pub struct Reply {
    pub content: String,
    pub usage: Option<Value>,
    pub finish_reason: String,
}

impl Client {
    pub fn new(cfg: &Llm) -> Result<Self> {
        let key = cfg.api_key()?;
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .http_status_as_error(false)
            .user_agent(concat!("logscan/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let extra = serde_json::to_value(&cfg.extra_body).context("llm.extra_body")?;
        Ok(Self {
            agent,
            base: cfg.base_url.trim_end_matches('/').to_string(),
            key,
            max_tokens: cfg.max_tokens,
            json_mode: cfg.json_mode,
            extra,
        })
    }

    fn check(resp: &mut ureq::http::Response<ureq::Body>) -> Result<Value> {
        let status = resp.status().as_u16();
        let body = resp.body_mut().with_config().limit(16 * 1024 * 1024).read_to_string().unwrap_or_default();
        if !(200..300).contains(&status) {
            bail!("HTTP {status}: {}", crate::model::truncate(body.trim(), 600));
        }
        serde_json::from_str(&body).with_context(|| format!("response is not JSON: {}", crate::model::truncate(&body, 300)))
    }

    pub fn models(&self) -> Result<Vec<String>> {
        let mut resp = self
            .agent
            .get(format!("{}/models", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .call()
            .map_err(|e| anyhow!("GET /models: {e}"))?;
        let v = Self::check(&mut resp)?;
        let mut ids: Vec<String> = v["data"]
            .as_array()
            .map(|a| a.iter().filter_map(|m| m["id"].as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        ids.sort();
        Ok(ids)
    }

    pub fn chat(&self, model: &str, system: &str, user: &str) -> Result<Reply> {
        let mut body = json!({
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
        });
        if self.json_mode {
            body["response_format"] = json!({"type": "json_object"});
        }
        if let (Some(b), Some(extra)) = (body.as_object_mut(), self.extra.as_object()) {
            for (k, v) in extra {
                b.insert(k.clone(), v.clone());
            }
        }
        let mut resp = self
            .agent
            .post(format!("{}/chat/completions", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .send_json(&body)
            .map_err(|e| anyhow!("POST /chat/completions: {e}"))?;
        let v = Self::check(&mut resp)?;
        let choice = &v["choices"][0];
        let content = choice["message"]["content"]
            .as_str()
            .ok_or_else(|| anyhow!("no message content in response: {}", crate::model::truncate(&v.to_string(), 300)))?;
        Ok(Reply {
            content: strip_think(content),
            usage: v.get("usage").cloned(),
            finish_reason: choice["finish_reason"].as_str().unwrap_or("").to_string(),
        })
    }
}

static THINK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<think>.*?</think>").unwrap());

fn strip_think(s: &str) -> String {
    THINK.replace_all(s, "").trim().to_string()
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
    let start = content.find('{').ok_or_else(|| anyhow!("no JSON object in answer"))?;
    let end = content.rfind('}').ok_or_else(|| anyhow!("no JSON object in answer"))?;
    if end < start {
        bail!("no JSON object in answer");
    }
    let mut v: Verdict = serde_json::from_str(&content[start..=end]).context("answer JSON doesn't match the schema")?;
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

    #[test]
    fn strips_thinking() {
        assert_eq!(strip_think("<think>\na\n</think>\n{\"a\":1}"), "{\"a\":1}");
    }
}
