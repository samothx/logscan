//! Mails the Markdown report via sendmail (msmtp on anubis), only when there is something to report.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use chrono::Local;

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

/// RFC 5322 message, quoted-printable (keeps long evidence lines SMTP-safe). With `email.html`
/// it is multipart/alternative: the Markdown as text/plain plus an HTML rendering.
pub fn build_message(cfg: &Email, subject: &str, intro: &str, markdown: &str) -> String {
    let now = Local::now();
    let id = format!("<logscan.{}.{}@{}>", now.format("%Y%m%d%H%M%S"), std::process::id(), crate::scan::hostname());
    let body = format!("{intro}\n\n{markdown}");
    let mut m = String::new();
    m.push_str(&format!("From: logscan <{}>\r\n", cfg.from));
    m.push_str(&format!("To: {}\r\n", cfg.to.join(", ")));
    m.push_str(&format!("Subject: {}\r\n", ascii_subject(subject)));
    m.push_str(&format!("Date: {}\r\n", now.to_rfc2822()));
    m.push_str(&format!("Message-ID: {id}\r\n"));
    m.push_str("Auto-Submitted: auto-generated\r\n");
    m.push_str("MIME-Version: 1.0\r\n");
    if !cfg.html {
        m.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        m.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
        m.push_str(&quoted_printable(&body));
        return m;
    }
    let boundary = format!("=_logscan_{}_{}", now.timestamp(), std::process::id());
    m.push_str(&format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"));
    m.push_str("This is a MIME message: the report as plain text and as HTML.\r\n");
    for (ctype, content) in [("text/plain", body.clone()), ("text/html", markdown_to_html(subject, &body))] {
        m.push_str(&format!("\r\n--{boundary}\r\n"));
        m.push_str(&format!("Content-Type: {ctype}; charset=utf-8\r\n"));
        m.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
        m.push_str(&quoted_printable(&content));
    }
    m.push_str(&format!("\r\n--{boundary}--\r\n"));
    m
}

const CSS: &str = "body{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1f2328;max-width:960px;margin:16px}\
h1{font-size:20px;border-bottom:1px solid #d0d7de;padding-bottom:6px}\
h2{font-size:17px;margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:4px}\
h3{font-size:15px;margin:18px 0 4px}\
code{background:#f6f8fa;padding:1px 4px;border-radius:4px;font:12px ui-monospace,Menlo,Consolas,monospace}\
pre{background:#f6f8fa;padding:8px 10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}\
pre code{padding:0;font-size:12px}ul{padding-left:22px}li{margin:2px 0}";

/// Renders Markdown to a standalone HTML page. Raw HTML in the input is escaped, never passed
/// through: titles and evidence contain attacker-chosen text (paths, user agents).
pub fn markdown_to_html(title: &str, md: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser, html};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    let events = Parser::new_ext(md, opts).map(|e| match e {
        Event::Html(t) | Event::InlineHtml(t) => Event::Text(t),
        other => other,
    });
    let mut body = String::new();
    html::push_html(&mut body, events);
    let mut esc_title = String::new();
    pulldown_cmark_escape::escape_html(&mut esc_title, title).expect("writing to a String");
    format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{esc_title}</title><style>{CSS}</style></head>\n<body>\n{body}</body></html>\n"
    )
}

/// Subjects stay ASCII so no RFC 2047 encoding is needed.
fn ascii_subject(s: &str) -> String {
    s.chars().map(|c| if c == '≥' { '>' } else if c.is_ascii() && !c.is_ascii_control() { c } else { '?' }).collect()
}

pub fn quoted_printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 10);
    for line in s.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let bytes = line.as_bytes();
        let mut col = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let last = i + 1 == bytes.len();
            let trailing_space = (b == b' ' || b == b'\t') && last;
            let enc = if trailing_space || b == b'=' || !(32..=126).contains(&b) && b != b'\t' {
                format!("={b:02X}")
            } else {
                (b as char).to_string()
            };
            if col + enc.len() > 75 {
                out.push_str("=\r\n");
                col = 0;
            }
            out.push_str(&enc);
            col += enc.len();
        }
        out.push_str("\r\n");
    }
    out
}

pub fn send(cfg: &Email, message: &str) -> Result<()> {
    let mut child = Command::new(&cfg.sendmail)
        .arg("-i")
        .arg("-f")
        .arg(&cfg.from)
        .arg("--")
        .args(&cfg.to)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", cfg.sendmail.display()))?;
    child.stdin.take().expect("piped").write_all(message.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{} failed ({}): {}", cfg.sendmail.display(), out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qp_encodes_and_wraps() {
        let qp = quoted_printable("a=b ≥ x \n");
        assert_eq!(qp, "a=3Db =E2=89=A5 x=20\r\n\r\n");
        let long = "x".repeat(200);
        let enc = quoted_printable(&long);
        assert!(enc.lines().all(|l| l.len() <= 76), "{enc}");
        // Decoding soft breaks gives the original back.
        assert_eq!(enc.replace("=\r\n", "").trim_end(), long);
    }

    #[test]
    fn html_escapes_attacker_markup() {
        let md = "# r\n\n### Sensitive file served: x.de/<img src=http://evil/x>\n\n<script>alert(1)</script>\n\n```\nGET /<b>x</b>\n```\n";
        let h = markdown_to_html("t <x>", md);
        assert!(!h.contains("<img") && !h.contains("<script>") && !h.contains("<b>"), "{h}");
        assert!(h.contains("&lt;img") && h.contains("&lt;script&gt;") && h.contains("<title>t &lt;x&gt;</title>"));
        assert!(h.contains("<h3>") && h.contains("<pre><code>"));
    }

    #[test]
    fn multipart_has_both_parts() {
        let cfg = Email { to: vec!["a@b.de".into()], from: "c@d.de".into(), ..Email::default() };
        let m = build_message(&cfg, "s", "intro", "# x");
        assert!(m.contains("multipart/alternative") && m.contains("text/plain") && m.contains("text/html"));
        assert_eq!(m.matches("--=_logscan_").count(), 3);
    }

    #[test]
    fn subject_is_ascii() {
        assert_eq!(ascii_subject("2 new ≥ medium – ok"), "2 new > medium ? ok");
    }
}
