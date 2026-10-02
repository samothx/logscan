use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::Deserialize;

use crate::model::Severity;

pub const DEFAULT_CONFIG: &str = "/etc/logscan/config.toml";

/// Name of the list in `[lists]` that defines trusted networks (drives the `trusted` field).
pub const TRUSTED_LIST: &str = "trusted_networks";

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    /// Named lists, referenced from rules as "@name".
    pub lists: BTreeMap<String, Vec<String>>,
    pub sources: Sources,
    pub notify: Notify,
    pub email: Email,
    pub llm: Llm,
    #[serde(skip)]
    pub trusted: Vec<IpNet>,
    #[serde(skip)]
    pub base_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub state_dir: PathBuf,
    /// Relative paths are resolved against the config file's directory.
    pub rules_dir: PathBuf,
    pub skills_dir: PathBuf,
    pub report_retention_days: u32,
    /// Window used on the first run (no state yet).
    pub default_window_hours: u32,
    /// Catch-up cap after the timer missed runs.
    pub max_window_hours: u32,
}

impl Default for General {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("/var/lib/logscan"),
            rules_dir: PathBuf::from("rules.d"),
            skills_dir: PathBuf::from("skills.d"),
            report_retention_days: 90,
            default_window_hours: 24,
            max_window_hours: 168,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sources {
    pub journalctl: PathBuf,
    /// Read in order; missing files are skipped, `.gz` is decompressed.
    pub nginx_access_logs: Vec<PathBuf>,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            nginx_access_logs: vec![
                "/var/log/nginx/access.log".into(),
                "/var/log/nginx/access.log.1".into(),
                "/var/log/nginx/access.log.2.gz".into(),
            ],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Notify {
    pub enabled: bool,
    pub command: PathBuf,
    /// Findings at or above this severity trigger an alert push.
    pub min_severity: Severity,
    /// Also push a short daily summary (low priority).
    pub digest: bool,
    /// An alert with the same fingerprint is not pushed again for this many days.
    pub repeat_suppress_days: u32,
}

impl Default for Notify {
    fn default() -> Self {
        Self {
            enabled: true,
            command: PathBuf::from("/usr/local/bin/ntfy-dispatcher"),
            min_severity: Severity::High,
            digest: true,
            repeat_suppress_days: 7,
        }
    }
}

/// Mails the Markdown report, but only when there is something to report.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Email {
    pub enabled: bool,
    pub to: Vec<String>,
    /// Envelope sender and From: header. Must be an address the relay accepts.
    pub from: String,
    pub sendmail: PathBuf,
    /// A finding at or above this severity, not mailed within `repeat_days`, triggers a mail.
    pub min_severity: Severity,
    pub repeat_days: u32,
    /// Also mail when an LLM skill's assessment isn't "clean".
    pub on_llm_suspicion: bool,
    /// Also mail when the run had errors.
    pub on_errors: bool,
    /// multipart/alternative with an HTML rendering of the report (plain text is always included).
    pub html: bool,
}

impl Default for Email {
    fn default() -> Self {
        Self {
            enabled: false,
            to: Vec::new(),
            from: String::new(),
            sendmail: PathBuf::from("/usr/sbin/sendmail"),
            min_severity: Severity::Medium,
            repeat_days: 7,
            on_llm_suspicion: true,
            on_errors: true,
            html: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Llm {
    pub enabled: bool,
    /// Label only ("venice", "deepseek", …); the API is OpenAI-compatible either way.
    pub provider: String,
    /// Base URL without /chat/completions, e.g. https://api.venice.ai/api/v1
    pub base_url: String,
    pub model: String,
    /// Plain file with the key. Relative names are looked up in $CREDENTIALS_DIRECTORY
    /// (systemd LoadCredential=) first. $LOGSCAN_API_KEY overrides.
    pub api_key_file: PathBuf,
    pub timeout_secs: u64,
    pub max_tokens: u32,
    /// Cap on the data sent to the model, summed over all skills of one run.
    pub max_total_chars: usize,
    /// Send `response_format: {"type": "json_object"}`.
    pub json_mode: bool,
    /// Replace IP addresses with stable pseudonyms before sending; mapped back afterwards.
    pub pseudonymize_ips: bool,
    /// Merged into the request body as-is (provider-specific knobs).
    pub extra_body: toml::Table,
    /// Severity cap for LLM findings (it has no ground truth; see README).
    pub max_severity: Severity,
}

impl Default for Llm {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "venice".into(),
            base_url: "https://api.venice.ai/api/v1".into(),
            model: "deepseek-v4-flash".into(),
            api_key_file: PathBuf::from("/etc/logscan/llm-api-key"),
            timeout_secs: 300,
            max_tokens: 8000,
            max_total_chars: 250_000,
            json_mode: true,
            pseudonymize_ips: true,
            extra_body: toml::Table::new(),
            max_severity: Severity::High,
        }
    }
}

impl Llm {
    pub fn api_key(&self) -> Result<String> {
        if let Ok(k) = std::env::var("LOGSCAN_API_KEY")
            && !k.trim().is_empty()
        {
            return Ok(k.trim().to_string());
        }
        let path = self.key_path();
        let key = std::fs::read_to_string(&path)
            .with_context(|| format!("reading API key from {}", path.display()))?;
        let key = key.trim();
        if key.is_empty() {
            bail!("API key file {} is empty", path.display());
        }
        Ok(key.to_string())
    }

    fn key_path(&self) -> PathBuf {
        if self.api_key_file.is_relative()
            && let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY")
        {
            return Path::new(&dir).join(&self.api_key_file);
        }
        self.api_key_file.clone()
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        Self::parse(&text, base).with_context(|| format!("config {}", path.display()))
    }

    pub fn parse(text: &str, base_dir: PathBuf) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text)?;
        cfg.base_dir = base_dir;
        cfg.trusted = cfg
            .lists
            .get(TRUSTED_LIST)
            .map(|l| {
                l.iter()
                    .map(|n| n.parse::<IpNet>().with_context(|| format!("{TRUSTED_LIST}: bad network {n:?}")))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        if cfg.email.enabled && (cfg.email.to.is_empty() || !cfg.email.from.contains('@')) {
            bail!("email.enabled requires email.to and email.from");
        }
        if cfg.llm.enabled && (cfg.llm.base_url.is_empty() || cfg.llm.model.is_empty()) {
            bail!("llm.enabled requires llm.base_url and llm.model");
        }
        Ok(cfg)
    }

    pub fn is_trusted(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>()
            .map(|a| self.trusted.iter().any(|n| n.contains(&a)))
            .unwrap_or(false)
    }

    pub fn rules_dir(&self) -> PathBuf {
        self.base_dir.join(&self.general.rules_dir)
    }

    pub fn skills_dir(&self) -> PathBuf {
        self.base_dir.join(&self.general.skills_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let cfg = Config::parse(include_str!("../defaults/config.toml"), "defaults".into()).unwrap();
        assert!(cfg.is_trusted("10.8.1.5"));
        assert!(cfg.is_trusted("fd00:c0ff:ee::5"));
        assert!(!cfg.is_trusted("8.8.8.8"));
        assert!(!cfg.is_trusted("not-an-ip"));
    }
}
