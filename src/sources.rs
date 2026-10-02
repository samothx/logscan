//! Log readers: the systemd journal (via `journalctl -o json`) and nginx access logs.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, FixedOffset, Local, TimeZone};
use flate2::read::MultiGzDecoder;
use regex::Regex;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub ts: DateTime<Local>,
    pub priority: u8,
    /// SYSLOG_IDENTIFIER, falling back to the unit / comm.
    pub ident: String,
    pub unit: String,
    pub kernel: bool,
    /// ANSI escapes stripped.
    pub message: String,
}

impl JournalEntry {
    pub fn line(&self) -> String {
        format!("{} {}: {}", self.ts.format("%m-%d %H:%M:%S"), self.ident, self.message)
    }
}

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap());

pub fn strip_ansi(s: &str) -> String {
    if s.contains('\x1b') { ANSI.replace_all(s, "").into_owned() } else { s.to_string() }
}

/// Streams all journal entries in [since, until). Needs membership in systemd-journal (or adm).
pub fn read_journal(
    journalctl: &Path,
    since: DateTime<Local>,
    until: DateTime<Local>,
    mut f: impl FnMut(JournalEntry),
) -> Result<u64> {
    let mut child = Command::new(journalctl)
        .args([
            "--no-pager",
            "--quiet",
            "--merge",
            "-o",
            "json",
            "--output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,_COMM,_TRANSPORT",
        ])
        .arg(format!("--since=@{}", since.timestamp()))
        .arg(format!("--until=@{}", until.timestamp()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", journalctl.display()))?;

    let stdout = child.stdout.take().expect("piped");
    let mut n = 0;
    for line in BufReader::new(stdout).lines() {
        let line = line.context("reading journalctl output")?;
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        if let Some(e) = parse_entry(&v) {
            n += 1;
            f(e);
        }
    }
    let out = child.wait_with_output().context("waiting for journalctl")?;
    if !out.status.success() {
        bail!(
            "journalctl failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(n)
}

fn field(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) => Some(s.clone()),
        // Non-UTF-8 payloads come as byte arrays.
        Value::Array(a) => {
            let bytes: Vec<u8> = a.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

fn parse_entry(v: &Value) -> Option<JournalEntry> {
    let usec: i64 = field(v, "__REALTIME_TIMESTAMP")?.parse().ok()?;
    let ts = Local.timestamp_micros(usec).single()?;
    let message = strip_ansi(&field(v, "MESSAGE")?);
    let unit = field(v, "_SYSTEMD_UNIT").unwrap_or_default();
    let kernel = field(v, "_TRANSPORT").as_deref() == Some("kernel");
    let ident = field(v, "SYSLOG_IDENTIFIER")
        .or_else(|| field(v, "_COMM"))
        .unwrap_or_else(|| if kernel { "kernel".into() } else { unit.clone() });
    let priority = field(v, "PRIORITY").and_then(|p| p.parse().ok()).unwrap_or(6);
    Some(JournalEntry { ts, priority, ident, unit, kernel, message })
}

// ---------------------------------------------------------------------------------------
// nginx
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Request {
    pub ts: DateTime<FixedOffset>,
    pub ip: String,
    pub method: String,
    /// Raw request target as logged (still percent-encoded).
    pub target: String,
    pub status: u16,
    pub bytes: u64,
    pub referer: String,
    pub ua: String,
    pub host: String,
    pub raw: String,
}

impl Request {
    /// Path without the query string.
    pub fn path(&self) -> &str {
        self.target.split(['?', '#']).next().unwrap_or("")
    }

    pub fn query(&self) -> &str {
        self.target.split_once('?').map(|(_, q)| q).unwrap_or("")
    }
}

// vhost_combined + sn="$host": see /etc/nginx/nginx.conf
static ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+) \S+ (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-) "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"(?: sn="([^"]*)")?"#,
    )
    .unwrap()
});

pub fn parse_access_line(line: &str) -> Option<Request> {
    let c = ACCESS.captures(line)?;
    let ts = DateTime::parse_from_str(&c[3], "%d/%b/%Y:%H:%M:%S %z").ok()?;
    let request = &c[4];
    let mut parts = request.splitn(3, ' ');
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(m), Some(t)) => (m.to_string(), t.to_string()),
        // Garbage / TLS handshakes on :80 / empty request
        (Some(m), None) => (String::new(), m.to_string()),
        _ => (String::new(), String::new()),
    };
    Some(Request {
        ts,
        ip: c[1].to_string(),
        method,
        target,
        status: c[5].parse().ok()?,
        bytes: c[6].parse().unwrap_or(0),
        referer: c[7].to_string(),
        ua: c[8].to_string(),
        host: c.get(9).map(|m| m.as_str().to_string()).unwrap_or_default(),
        raw: line.to_string(),
    })
}

/// Reads one access log (plain or .gz). Returns (parsed in window, unparsable lines).
pub fn read_access_log(
    path: &Path,
    since: DateTime<Local>,
    until: DateTime<Local>,
    out: &mut Vec<Request>,
) -> Result<u64> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader: Box<dyn Read> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(MultiGzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut bad = 0;
    let mut buf = Vec::new();
    let mut r = BufReader::new(reader);
    loop {
        buf.clear();
        if r.read_until(b'\n', &mut buf).with_context(|| format!("reading {}", path.display()))? == 0
        {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        match parse_access_line(line) {
            Some(req) => {
                if req.ts >= since && req.ts < until {
                    out.push(req);
                }
            }
            None => bad += 1,
        }
    }
    Ok(bad)
}

/// Lenient percent-decoding, applied twice to catch double encoding. Lowercased.
pub fn decode(s: &str) -> String {
    let once = percent_decode(s);
    let twice = if once.contains('%') { percent_decode(&once) } else { once };
    twice.replace('+', " ").to_ascii_lowercase()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        // nginx escapes non-printables in the log as \xHH
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1] == b'x'
            && let (Some(h), Some(l)) = (hex(b[i + 2]), hex(b[i + 3]))
        {
            out.push(h * 16 + l);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

// ---------------------------------------------------------------------------------------
// Plain text report files (rkhunter, chkrootkit) and file metadata
// ---------------------------------------------------------------------------------------

static TIME_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[\d{2}:\d{2}:\d{2}\] ?").unwrap());
static SECTION_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s{0,3}(?:Checking|Searching|Info:|Warning:|WARNING:)").unwrap());

/// One line of a text log plus its continuation lines.
pub struct TextLine {
    pub line: String,
    pub context: Vec<String>,
    /// From a leading "YYYY-MM-DD HH:MM:SS" (dpkg.log style); lets the scanner window each line.
    pub ts: Option<DateTime<Local>>,
}

static DATE_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})").unwrap());

fn line_ts(l: &str) -> Option<DateTime<Local>> {
    let c = DATE_PREFIX.captures(l)?;
    let n = chrono::NaiveDateTime::parse_from_str(&c[1].replace('T', " "), "%Y-%m-%d %H:%M:%S").ok()?;
    Local.from_local_datetime(&n).earliest()
}

/// Reads a text file if it was modified at/after `since`. `Ok(None)` = not modified in window.
/// Continuation: after a line ending in ':' the following lines up to a blank line (chkrootkit
/// style, max 500 lines), otherwise following lines indented by ≥4 spaces (rkhunter style, max 20).
pub fn read_text_file(path: &Path, since: DateTime<Local>) -> Result<Option<(DateTime<Local>, Vec<TextLine>)>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };
    let mtime: DateTime<Local> = meta.modified()?.into();
    if mtime < since {
        return Ok(None);
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<String> = text.lines().map(|l| TIME_PREFIX.replace(l, "").into_owned()).collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        let block = l.trim_end().ends_with(':');
        let mut context = Vec::new();
        for next in lines.iter().skip(i + 1).take(if block { 500 } else { 20 }) {
            if next.trim().is_empty() || SECTION_START.is_match(next) {
                break;
            }
            if block || next.starts_with("    ") {
                context.push(next.trim_end().to_string());
            } else {
                break;
            }
        }
        out.push(TextLine { line: l.trim().to_string(), context, ts: line_ts(l) });
    }
    Ok(Some((mtime, out)))
}

pub struct Changed {
    pub path: String,
    pub ctime: DateTime<Local>,
    pub mtime: DateTime<Local>,
}

/// Paths (and direct children of directories) whose ctime is in [since, until).
/// Missing paths are skipped silently; other errors are returned as messages.
pub fn changed_paths(paths: &[String], since: DateTime<Local>, until: DateTime<Local>) -> (Vec<Changed>, Vec<String>) {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let check = |p: &Path, out: &mut Vec<Changed>| -> std::io::Result<std::fs::Metadata> {
        let m = std::fs::symlink_metadata(p)?;
        let ctime = Local.timestamp_opt(m.ctime(), 0).single();
        let mtime = Local.timestamp_opt(m.mtime(), 0).single();
        if let (Some(c), Some(mt)) = (ctime, mtime)
            && c >= since
            && c < until
        {
            out.push(Changed { path: p.display().to_string(), ctime: c, mtime: mt });
        }
        Ok(m)
    };
    for p in paths {
        let path = Path::new(p);
        match check(path, &mut out) {
            Ok(m) if m.is_dir() => match std::fs::read_dir(path) {
                Ok(rd) => {
                    for e in rd.flatten() {
                        let _ = check(&e.path(), &mut out);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    // e.g. /etc/sudoers.d (0750): the directory's own ctime still covers adds/removes.
                }
                Err(e) => errors.push(format!("{p}: {e}")),
            },
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("{p}: {e}")),
        }
    }
    (out, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"34.146.129.243 - - [02/Oct/2026:00:36:07 +0200] "GET /client/en?a=1 HTTP/1.1" 200 22685 "https://gaylynmorgan.com/" "Mozilla/5.0 (X11)" sn="gaylynmorgan.com""#;

    #[test]
    fn parses_vhost_combined() {
        let r = parse_access_line(LINE).unwrap();
        assert_eq!(r.ip, "34.146.129.243");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path(), "/client/en");
        assert_eq!(r.query(), "a=1");
        assert_eq!(r.status, 200);
        assert_eq!(r.bytes, 22685);
        assert_eq!(r.host, "gaylynmorgan.com");
    }

    #[test]
    fn parses_garbage_request() {
        let l = r#"1.2.3.4 - - [02/Oct/2026:00:36:07 +0200] "\x16\x03\x01" 400 157 "-" "-" sn="_""#;
        let r = parse_access_line(l).unwrap();
        assert_eq!(r.method, "");
        assert_eq!(r.status, 400);
        let l = r#"1.2.3.4 - - [02/Oct/2026:00:36:07 +0200] "" 400 0 "-" "-" sn="_""#;
        assert!(parse_access_line(l).is_some());
    }

    #[test]
    fn dated_lines_get_a_timestamp() {
        let t = line_ts("2026-10-01 06:44:06 upgrade openssl:amd64 3.5.7-1 3.5.7-2").unwrap();
        assert_eq!(t.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-10-01 06:44:06");
        assert!(line_ts("[06:25:54] Warning: x").is_none());
    }

    #[test]
    fn decodes_double_encoding() {
        assert_eq!(decode("/a/%252e%252e/%2E%2E/x"), "/a/../../x");
        assert_eq!(decode("/q?x=union+select"), "/q?x=union select");
        assert_eq!(decode("%"), "%");
        assert_eq!(decode("%4"), "%4");
    }
}
