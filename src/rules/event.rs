//! A uniform view over all log sources so rules can address fields by name.

use std::borrow::Cow;

use chrono::{DateTime, Local};

use crate::sources::{JournalEntry, Request, decode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    Journal,
    Nginx,
    File,
    FileChanged,
}

impl SourceKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Journal => "journal",
            Self::Nginx => "nginx",
            Self::File => "file",
            Self::FileChanged => "file_changed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NginxEvent {
    pub req: Request,
    /// Percent-decoded (twice), lowercased path without query.
    pub path: String,
    /// Decoded, lowercased query string.
    pub query: String,
    pub trusted: bool,
}

impl NginxEvent {
    pub fn new(req: Request, trusted: bool) -> Self {
        let path = decode(req.path());
        let query = decode(req.query());
        Self { req, path, query, trusted }
    }
}

#[derive(Debug, Clone)]
pub struct FileLine {
    pub file: String,
    pub line: String,
    /// Following indented continuation lines (rkhunter prints details that way).
    pub context: Vec<String>,
    pub ts: DateTime<Local>,
}

#[derive(Debug, Clone)]
pub struct FileChange {
    /// The watched path (from a rule's `paths`) this change belongs to.
    pub root: String,
    pub path: String,
    pub ctime: DateTime<Local>,
    pub mtime: DateTime<Local>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Journal(JournalEntry),
    Nginx(NginxEvent),
    File(FileLine),
    FileChanged(FileChange),
}

impl Event {
    pub fn kind(&self) -> SourceKind {
        match self {
            Self::Journal(_) => SourceKind::Journal,
            Self::Nginx(_) => SourceKind::Nginx,
            Self::File(_) => SourceKind::File,
            Self::FileChanged(_) => SourceKind::FileChanged,
        }
    }

    pub fn ts(&self) -> DateTime<Local> {
        match self {
            Self::Journal(e) => e.ts,
            Self::Nginx(e) => e.req.ts.with_timezone(&Local),
            Self::File(e) => e.ts,
            Self::FileChanged(e) => e.ctime,
        }
    }

    /// Field lookup for rule conditions. Unknown fields → None.
    pub fn get(&self, field: &str) -> Option<Cow<'_, str>> {
        let b = |s: &str| Some(Cow::Owned(s.to_string()));
        match self {
            Self::Journal(e) => match field {
                "ident" => Some(Cow::Borrowed(e.ident.as_str())),
                "unit" => Some(Cow::Borrowed(e.unit.as_str())),
                "message" => Some(Cow::Borrowed(e.message.as_str())),
                "priority" => b(&e.priority.to_string()),
                "kernel" => b(if e.kernel { "true" } else { "false" }),
                _ => None,
            },
            Self::Nginx(e) => match field {
                "ip" => Some(Cow::Borrowed(e.req.ip.as_str())),
                "method" => Some(Cow::Borrowed(e.req.method.as_str())),
                "path" => Some(Cow::Borrowed(e.path.as_str())),
                "query" => Some(Cow::Borrowed(e.query.as_str())),
                "request" => Some(if e.query.is_empty() {
                    Cow::Borrowed(e.path.as_str())
                } else {
                    Cow::Owned(format!("{}?{}", e.path, e.query))
                }),
                "target" => Some(Cow::Borrowed(e.req.target.as_str())),
                "status" => b(&e.req.status.to_string()),
                "bytes" => b(&e.req.bytes.to_string()),
                "host" => Some(Cow::Owned(e.req.host.to_ascii_lowercase())),
                "ua" => Some(Cow::Borrowed(e.req.ua.as_str())),
                "referer" => Some(Cow::Borrowed(e.req.referer.as_str())),
                "trusted" => b(if e.trusted { "true" } else { "false" }),
                _ => None,
            },
            Self::File(e) => match field {
                "file" => Some(Cow::Borrowed(e.file.as_str())),
                "line" => Some(Cow::Borrowed(e.line.as_str())),
                "context" => Some(Cow::Owned(e.context.join("\n"))),
                _ => None,
            },
            Self::FileChanged(e) => match field {
                "root" => Some(Cow::Borrowed(e.root.as_str())),
                "path" => Some(Cow::Borrowed(e.path.as_str())),
                "ctime" => b(&e.ctime.format("%Y-%m-%d %H:%M:%S").to_string()),
                "mtime" => b(&e.mtime.format("%Y-%m-%d %H:%M:%S").to_string()),
                _ => None,
            },
        }
    }

    /// One-line rendering used as evidence.
    pub fn raw(&self) -> String {
        match self {
            Self::Journal(e) => e.line(),
            Self::Nginx(e) => e.req.raw.clone(),
            Self::File(e) => {
                let mut s = format!("{}: {}", e.file, e.line.trim());
                for c in e.context.iter().take(4) {
                    s.push_str(" | ");
                    s.push_str(c.trim());
                }
                s
            }
            Self::FileChanged(e) => format!(
                "{} changed (ctime {}, mtime {})",
                e.path,
                e.ctime.format("%Y-%m-%d %H:%M:%S"),
                e.mtime.format("%Y-%m-%d %H:%M:%S")
            ),
        }
    }
}

pub const NUMERIC_FIELDS: &[&str] = &["status", "bytes", "priority"];

pub fn known_fields(kind: SourceKind) -> &'static [&'static str] {
    match kind {
        SourceKind::Journal => &["ident", "unit", "message", "priority", "kernel"],
        SourceKind::Nginx => &[
            "ip", "method", "path", "query", "request", "target", "status", "bytes", "host", "ua",
            "referer", "trusted",
        ],
        SourceKind::File => &["file", "line", "context"],
        SourceKind::FileChanged => &["root", "path", "ctime", "mtime"],
    }
}
