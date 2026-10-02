//! Pushes via `ntfy-dispatcher emit`. Events: logscan.alert / logscan.digest / logscan.error.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::Notify;
use crate::model::{Finding, Origin, Report, Severity, truncate};
use crate::state::State;

pub const EVENT_ALERT: &str = "logscan.alert";
pub const EVENT_DIGEST: &str = "logscan.digest";
pub const EVENT_ERROR: &str = "logscan.error";

pub struct Message {
    pub event: &'static str,
    pub title: String,
    pub body: String,
    pub priority: Option<u8>,
}

/// Marks repeats (pushed within repeat_suppress_days) and returns the findings to push.
pub fn select_alerts<'a>(report: &'a mut Report, cfg: &Notify, state: &State, now: i64) -> Vec<&'a Finding> {
    let window = i64::from(cfg.repeat_suppress_days) * 86_400;
    for f in report.findings.iter_mut() {
        if f.severity >= cfg.min_severity
            && let Some(t) = state.alerted.get(&f.fingerprint)
        {
            f.repeat = now - *t < window;
        }
    }
    report
        .findings
        .iter()
        .filter(|f| f.severity >= cfg.min_severity && !f.repeat)
        .collect()
}

fn label(f: &Finding) -> String {
    let ai = if f.origin == Origin::Llm { "[AI] " } else { "" };
    format!("{} {ai}{}", f.severity.to_string().to_uppercase(), f.title)
}

pub fn alert_message(host: &str, alerts: &[&Finding], report_path: &str) -> Message {
    let max = alerts.iter().map(|f| f.severity).max().unwrap_or(Severity::High);
    let mut body = String::new();
    for f in alerts.iter().take(12) {
        body.push_str(&format!("• {}\n", truncate(&label(f), 220)));
    }
    if alerts.len() > 12 {
        body.push_str(&format!("… and {} more\n", alerts.len() - 12));
    }
    body.push_str(&format!("\nReport: {report_path}"));
    Message {
        event: EVENT_ALERT,
        title: format!("{host}: {} security finding(s), max {max}", alerts.len()),
        body,
        priority: Some(if max >= Severity::Critical { 5 } else { 4 }),
    }
}

pub fn digest_message(r: &Report, report_path: &str) -> Message {
    let mut body = format!(
        "critical {} · high {} · medium {} · low {}\n",
        r.count_at(Severity::Critical),
        r.count_at(Severity::High),
        r.count_at(Severity::Medium),
        r.count_at(Severity::Low)
    );
    body.push_str(&format!(
        "{} journal entries, {} nginx requests, {} unmatched\n",
        r.stats.journal_entries, r.stats.nginx_requests, r.stats.residue_events
    ));
    for v in &r.llm {
        body.push_str(&format!("AI {}: {} ({})\n", v.skill, v.assessment, truncate(&v.summary, 160)));
    }
    for st in r.stats.rules.iter().take(8) {
        body.push_str(&format!("{}: {}\n", st.title, st.total));
    }
    let top: Vec<&Finding> = r.findings.iter().filter(|f| f.severity >= Severity::Medium).take(6).collect();
    if !top.is_empty() {
        body.push('\n');
        for f in top {
            body.push_str(&format!("• {}\n", truncate(&label(f), 160)));
        }
    }
    if !r.errors.is_empty() {
        body.push_str(&format!("\n{} error(s), see report\n", r.errors.len()));
    }
    body.push_str(&format!("\nReport: {report_path}"));
    Message {
        event: EVENT_DIGEST,
        title: format!("{}: daily log scan", r.host),
        body,
        priority: None,
    }
}

pub fn error_message(host: &str, what: &str) -> Message {
    Message {
        event: EVENT_ERROR,
        title: format!("{host}: log scan problem"),
        body: truncate(what, 3000),
        priority: None,
    }
}

pub fn send(cfg: &Notify, m: &Message) -> Result<()> {
    let mut cmd = Command::new(&cfg.command);
    cmd.args(["emit", "--event", m.event, "--title", &m.title, "--body", "-"]);
    if let Some(p) = m.priority {
        cmd.args(["--priority", &p.to_string()]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", cfg.command.display()))?;
    child.stdin.take().expect("piped").write_all(m.body.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("ntfy-dispatcher emit failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
