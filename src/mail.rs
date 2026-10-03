//! Decides whether a report is worth mailing; building and sending is opskit::mail.

use anyhow::Result;
use opskit::mail::Mailer;

use crate::config::Email;
use crate::model::{Report, Severity};
use crate::state::State;

/// Why a report is (or isn't) worth mailing.
pub struct Decision {
    pub send: bool,
    pub reasons: Vec<String>,
    /// Findings that count as new for this mail; recorded in state after sending.
    pub fingerprints: Vec<String>,
}

pub fn decide(r: &Report, cfg: &Email, state: &State, now: i64) -> Decision {
    let window = i64::from(cfg.repeat_days) * 86_400;
    let fresh: Vec<&crate::model::Finding> = r
        .findings
        .iter()
        .filter(|f| f.severity >= cfg.min_severity)
        .filter(|f| state.emailed.get(&f.fingerprint).is_none_or(|t| now - *t >= window))
        .collect();
    let mut reasons = Vec::new();
    if !fresh.is_empty() {
        reasons.push(format!("{} new finding(s) ≥ {}", fresh.len(), cfg.min_severity));
    }
    if cfg.on_llm_suspicion {
        for v in r.llm.iter().filter(|v| v.assessment != "clean") {
            reasons.push(format!("AI skill {}: {}", v.skill, v.assessment));
        }
    }
    if cfg.on_errors && !r.errors.is_empty() {
        reasons.push(format!("{} error(s)", r.errors.len()));
    }
    Decision {
        send: !reasons.is_empty(),
        reasons,
        fingerprints: fresh.iter().map(|f| f.fingerprint.clone()).collect(),
    }
}

pub fn subject(r: &Report, d: &Decision) -> String {
    let counts: Vec<String> = [Severity::Critical, Severity::High, Severity::Medium]
        .iter()
        .filter_map(|s| {
            let n = r.count_at(*s);
            (n > 0).then(|| format!("{n} {s}"))
        })
        .collect();
    let what = if counts.is_empty() { "no findings".to_string() } else { counts.join(", ") };
    let new = if d.fingerprints.is_empty() { String::new() } else { format!(" ({} new)", d.fingerprints.len()) };
    format!("[logscan] {}: {what}{new}", short_host(&r.host))
}

fn short_host(h: &str) -> &str {
    h.split('.').next().unwrap_or(h)
}

fn mailer(cfg: &Email) -> Mailer {
    Mailer { app: "logscan".into(), from: cfg.from.clone(), to: cfg.to.clone(), sendmail: cfg.sendmail.clone(), html: cfg.html }
}

/// RFC 5322 message, quoted-printable. With `email.html` it is multipart/alternative: the
/// Markdown as text/plain plus an HTML rendering (raw HTML escaped, see opskit::mail).
pub fn build_message(cfg: &Email, subject: &str, intro: &str, markdown: &str) -> String {
    mailer(cfg).build_message(subject, intro, markdown)
}

pub fn send(cfg: &Email, message: &str) -> Result<()> {
    mailer(cfg).send(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_has_both_parts() {
        let cfg = Email { to: vec!["a@b.de".into()], from: "c@d.de".into(), ..Email::default() };
        let m = build_message(&cfg, "s", "intro", "# x");
        assert!(m.contains("multipart/alternative") && m.contains("text/plain") && m.contains("text/html"));
        assert_eq!(m.matches("--=_logscan_").count(), 3);
    }
}
