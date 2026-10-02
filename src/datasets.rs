//! Data views for LLM skills: redacted, templated, deduplicated, rare-first.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::LazyLock;

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Local};
use regex::Regex;
use serde::Deserialize;

use crate::config::Config;
use crate::model::{Report, truncate};
use crate::rules::engine::Stored;
use crate::rules::event::Event;

// ---------------------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------------------

static IP_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9A-Fa-f:.]*[:.][0-9A-Fa-f:.]*").unwrap());
static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+").unwrap());
static BEARER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}").unwrap());
static LONG_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9_-]{32,}").unwrap());
static SECRET_PARAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b((?:access_|refresh_|id_)?token|key|apikey|api_key|password|passwd|pwd|secret|auth|code|session|sessionid|sig|signature|jwt|otp|hash|nonce)=([^&\s]*)").unwrap()
});
static ALIAS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:ip|vpn)-\d+\b").unwrap());

/// Replaces IPs with stable aliases (`ip-N`, `vpn-N` for trusted networks) and masks secrets.
/// The same instance must be used for all data of one run so aliases are consistent.
pub struct Redactor {
    pseudonymize: bool,
    trusted: Vec<ipnet::IpNet>,
    fwd: HashMap<String, String>,
    rev: HashMap<String, String>,
}

impl Redactor {
    pub fn new(cfg: &Config) -> Self {
        Self { pseudonymize: cfg.llm.pseudonymize_ips, trusted: cfg.trusted.clone(), fwd: HashMap::new(), rev: HashMap::new() }
    }

    pub fn ip(&mut self, ip: &str) -> String {
        if !self.pseudonymize {
            return ip.to_string();
        }
        let Ok(addr) = ip.parse::<IpAddr>() else { return ip.to_string() };
        let canon = addr.to_string();
        if let Some(a) = self.fwd.get(&canon) {
            return a.clone();
        }
        let prefix = if self.trusted.iter().any(|n| n.contains(&addr)) { "vpn" } else { "ip" };
        let alias = format!("{prefix}-{}", self.fwd.len() + 1);
        self.fwd.insert(canon.clone(), alias.clone());
        self.rev.insert(alias.clone(), canon);
        alias
    }

    /// Masks secrets and IPs in free text.
    pub fn text(&mut self, s: &str) -> String {
        let s = BEARER.replace_all(s, "$1 <REDACTED>");
        let s = SECRET_PARAM.replace_all(&s, "$1=<REDACTED>");
        let s = EMAIL.replace_all(&s, "<EMAIL>");
        let s = LONG_TOKEN.replace_all(&s, "<TOKEN>");
        if !self.pseudonymize {
            return s.into_owned();
        }
        let src = s.as_ref();
        IP_CANDIDATE
            .replace_all(src, |c: &regex::Captures| {
                let whole = c.get(0).expect("match");
                let m = whole.as_str();
                // "Chrome/120.0.0.0", "v1.2.3.4": version numbers, not addresses.
                let prev = src[..whole.start()].chars().next_back();
                if matches!(prev, Some('/') | Some('v') | Some('V')) {
                    return m.to_string();
                }
                let t = m.trim_matches(|ch| ch == '.' || ch == ':');
                if t.len() >= 7 && t.parse::<IpAddr>().is_ok() { m.replace(t, &self.ip(t)) } else { m.to_string() }
            })
            .into_owned()
    }

    /// Maps aliases in LLM output back to real addresses.
    pub fn unmask(&self, s: &str) -> String {
        ALIAS
            .replace_all(s, |c: &regex::Captures| self.rev.get(&c[0]).cloned().unwrap_or_else(|| c[0].to_string()))
            .into_owned()
    }
}

// ---------------------------------------------------------------------------------------
// Templating
// ---------------------------------------------------------------------------------------

static T_UUID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap());
static T_ALIAS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:ip|vpn)-\d+\b").unwrap());
static T_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:0x)?[0-9a-f]*\d[0-9a-f]*[a-f][0-9a-f]*\b|\b[0-9a-f]{12,}\b").unwrap());
static T_NUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+").unwrap());

/// Collapses variable parts so similar lines dedupe: IPs/aliases, UUIDs, hex, numbers.
pub fn template(s: &str) -> String {
    let s = T_UUID.replace_all(s, "<UUID>");
    let s = T_ALIAS.replace_all(&s, "<IP>");
    let s = T_HEX.replace_all(&s, "<HEX>");
    T_NUM.replace_all(&s, "<N>").into_owned()
}

struct Bucket {
    count: u64,
    example: String,
    first: DateTime<Local>,
    last: DateTime<Local>,
    rank: u8,
}

/// Groups lines by template; renders "count× [first–last] example", rare (and low rank) first.
#[derive(Default)]
struct Dedup {
    buckets: BTreeMap<String, Bucket>,
}

impl Dedup {
    fn add(&mut self, key: String, example: impl FnOnce() -> String, ts: DateTime<Local>, rank: u8) {
        let b = self.buckets.entry(key).or_insert_with(|| Bucket { count: 0, example: example(), first: ts, last: ts, rank });
        b.count += 1;
        b.first = b.first.min(ts);
        b.last = b.last.max(ts);
        b.rank = b.rank.min(rank);
    }

    fn render(self, limit: usize) -> (String, usize) {
        let total = self.buckets.len();
        let mut v: Vec<Bucket> = self.buckets.into_values().collect();
        v.sort_by(|a, b| a.rank.cmp(&b.rank).then(a.count.cmp(&b.count)).then(a.first.cmp(&b.first)));
        let mut s = String::new();
        for b in v.iter().take(limit) {
            let when = if b.count == 1 {
                b.first.format("%m-%d %H:%M").to_string()
            } else {
                format!("{}–{}", b.first.format("%m-%d %H:%M"), b.last.format("%m-%d %H:%M"))
            };
            let _ = writeln!(s, "{}× [{when}] {}", b.count, b.example);
        }
        if total > limit {
            let _ = writeln!(s, "[{} more distinct lines omitted]", total - limit);
        }
        (s, total)
    }
}

// ---------------------------------------------------------------------------------------
// Dataset selection
// ---------------------------------------------------------------------------------------

pub const DATASETS: &[&str] = &[
    "journal.residue",
    "journal.filtered",
    "nginx.residue",
    "nginx.rare_success",
    "nginx.ip_profiles",
    "nginx.filtered",
    "findings",
    "stats",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDef {
    pub dataset: String,
    /// Max lines / profiles (default 300, ip_profiles 40).
    pub limit: Option<usize>,
    // journal filters
    #[serde(default)]
    pub ident: Vec<String>,
    #[serde(default)]
    pub unit: Vec<String>,
    pub message: Option<String>,
    pub priority_max: Option<u8>,
    // nginx filters
    #[serde(default)]
    pub host: Vec<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub method: Vec<String>,
    pub trusted: Option<bool>,
    pub path: Option<String>,
    /// nginx.rare_success: max occurrences of a path template to count as rare (default 3).
    pub rare_max: Option<u64>,
    /// *.filtered: also include events that rules matched (default true).
    pub include_matched: Option<bool>,
}

/// Compiled filters.
#[derive(Debug)]
pub struct Input {
    pub def: InputDef,
    message: Option<Regex>,
    path: Option<Regex>,
    status: Option<(i64, i64)>,
    host: Vec<Regex>,
}

fn glob(p: &str) -> Result<Regex> {
    Ok(Regex::new(&format!("(?i)^{}$", p.split('*').map(regex::escape).collect::<Vec<_>>().join(".*")))?)
}

impl Input {
    pub fn compile(def: InputDef) -> Result<Self> {
        if !DATASETS.contains(&def.dataset.as_str()) {
            bail!("unknown dataset '{}' (one of: {})", def.dataset, DATASETS.join(", "));
        }
        Ok(Self {
            message: def.message.as_deref().map(Regex::new).transpose()?,
            path: def.path.as_deref().map(Regex::new).transpose()?,
            status: def.status.as_deref().map(crate::rules::parse_range).transpose()?,
            host: def.host.iter().map(|h| glob(h)).collect::<Result<_>>()?,
            def,
        })
    }

    fn journal_ok(&self, e: &crate::sources::JournalEntry) -> bool {
        (self.def.ident.is_empty() || self.def.ident.contains(&e.ident))
            && (self.def.unit.is_empty() || self.def.unit.contains(&e.unit))
            && self.def.priority_max.is_none_or(|p| e.priority <= p)
            && self.message.as_ref().is_none_or(|r| r.is_match(&e.message))
    }

    fn nginx_ok(&self, n: &crate::rules::event::NginxEvent) -> bool {
        let r = &n.req;
        (self.host.is_empty() || self.host.iter().any(|h| h.is_match(&r.host)))
            && self.status.is_none_or(|(a, b)| i64::from(r.status) >= a && i64::from(r.status) <= b)
            && (self.def.method.is_empty() || self.def.method.iter().any(|m| m.eq_ignore_ascii_case(&r.method)))
            && self.def.trusted.is_none_or(|t| t == n.trusted)
            && self.path.as_ref().is_none_or(|p| p.is_match(&n.path))
    }
}

pub struct Ctx<'a> {
    pub events: &'a [Stored],
    pub report: &'a Report,
}

static STATIC_ASSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|mp4|webm)$|^/_next/static/|^/_next/image)").unwrap()
});

fn request_line(red: &mut Redactor, n: &crate::rules::event::NginxEvent) -> String {
    let r = &n.req;
    let target = truncate(&red.text(&r.target), 300);
    let ua = truncate(&red.text(&r.ua), 120);
    format!("{} {} {}{} → {} {}B ua=\"{}\"", red.ip(&r.ip), r.method, r.host, target, r.status, r.bytes, ua)
}

/// Renders one dataset. Returns the text and the number of distinct items it had.
pub fn build(input: &Input, ctx: &Ctx, red: &mut Redactor) -> Result<(String, usize)> {
    let limit = input.def.limit;
    let include_matched = input.def.include_matched.unwrap_or(true);
    Ok(match input.def.dataset.as_str() {
        "journal.residue" | "journal.filtered" => {
            let residue = input.def.dataset == "journal.residue";
            let mut d = Dedup::default();
            for s in ctx.events {
                let Event::Journal(e) = &s.ev else { continue };
                let keep = if residue { s.matched.is_none() } else { include_matched || s.matched.is_none() };
                if !keep || !input.journal_ok(e) {
                    continue;
                }
                let msg = red.text(&e.message);
                d.add(
                    format!("{}\u{0}{}", e.ident, template(&msg)),
                    || format!("{} (prio {}): {}", e.ident, e.priority, truncate(&msg, 400)),
                    e.ts,
                    e.priority,
                );
            }
            d.render(limit.unwrap_or(300))
        }
        "nginx.residue" | "nginx.filtered" => {
            let residue = input.def.dataset == "nginx.residue";
            let mut d = Dedup::default();
            for s in ctx.events {
                let Event::Nginx(n) = &s.ev else { continue };
                let keep = if residue { s.matched.is_none() } else { include_matched || s.matched.is_none() };
                if !keep || !input.nginx_ok(n) {
                    continue;
                }
                let key = format!("{}\u{0}{}\u{0}{}\u{0}{}", n.req.host, n.req.method, n.req.status / 100, template(&n.path));
                d.add(key, || request_line(red, n), n.req.ts.with_timezone(&Local), 0);
            }
            d.render(limit.unwrap_or(300))
        }
        "nginx.rare_success" => {
            let rare_max = input.def.rare_max.unwrap_or(3);
            let mut groups: BTreeMap<String, Vec<&crate::rules::event::NginxEvent>> = BTreeMap::new();
            for s in ctx.events {
                let Event::Nginx(n) = &s.ev else { continue };
                // Default: 2xx only (3xx are mostly http→https / www redirects). `status` overrides.
                let status_ok = if input.status.is_some() { true } else { (200..300).contains(&n.req.status) };
                if n.trusted || !status_ok || STATIC_ASSET.is_match(&n.path) || !input.nginx_ok(n) {
                    continue;
                }
                groups.entry(format!("{}\u{0}{}", n.req.host, template(&n.path))).or_default().push(n);
            }
            let mut d = Dedup::default();
            for (key, reqs) in groups {
                if reqs.len() as u64 > rare_max {
                    continue;
                }
                for n in reqs {
                    d.add(format!("{key}\u{0}{}", n.req.method), || request_line(red, n), n.req.ts.with_timezone(&Local), 0);
                }
            }
            d.render(limit.unwrap_or(300))
        }
        "nginx.ip_profiles" => ip_profiles(input, ctx, red, limit.unwrap_or(40)),
        "findings" => {
            let mut s = String::new();
            for f in &ctx.report.findings {
                let _ = writeln!(s, "- [{}] {} ({}×, rule {})", f.severity, red.text(&f.title), f.count, f.rule);
            }
            let n = ctx.report.findings.len();
            if n == 0 {
                s.push_str("(no rule findings)\n");
            }
            (s, n)
        }
        "stats" => {
            let mut s = String::new();
            for st in &ctx.report.stats.rules {
                let _ = writeln!(s, "- {}: {} events, {} groups", st.title, st.total, st.groups);
                for t in st.top.iter().take(limit.unwrap_or(10)) {
                    let _ = writeln!(s, "  - {}", red.text(t));
                }
            }
            (s, ctx.report.stats.rules.len())
        }
        other => return Err(anyhow!("unknown dataset {other}")),
    })
}

#[derive(Default)]
struct Profile {
    total: u64,
    status: BTreeMap<u16, u64>,
    methods: BTreeMap<String, u64>,
    hosts: BTreeMap<String, u64>,
    paths: BTreeMap<String, u64>,
    uas: BTreeMap<String, u64>,
    first: Option<DateTime<Local>>,
    last: Option<DateTime<Local>>,
}

fn top(m: &BTreeMap<String, u64>, n: usize) -> String {
    let mut v: Vec<(&String, &u64)> = m.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    v.iter().take(n).map(|(k, c)| format!("{k} ({c})")).collect::<Vec<_>>().join(", ")
}

fn ip_profiles(input: &Input, ctx: &Ctx, red: &mut Redactor, limit: usize) -> (String, usize) {
    let mut profiles: HashMap<&str, Profile> = HashMap::new();
    for s in ctx.events {
        let Event::Nginx(n) = &s.ev else { continue };
        if n.trusted || !input.nginx_ok(n) {
            continue;
        }
        let p = profiles.entry(n.req.ip.as_str()).or_default();
        let ts = n.req.ts.with_timezone(&Local);
        p.total += 1;
        *p.status.entry(n.req.status).or_default() += 1;
        *p.methods.entry(n.req.method.clone()).or_default() += 1;
        *p.hosts.entry(n.req.host.clone()).or_default() += 1;
        if p.paths.len() < 200 || p.paths.contains_key(&n.path) {
            *p.paths.entry(template(&n.path)).or_default() += 1;
        }
        *p.uas.entry(truncate(&n.req.ua, 100)).or_default() += 1;
        p.first = Some(p.first.map_or(ts, |f| f.min(ts)));
        p.last = Some(p.last.map_or(ts, |l| l.max(ts)));
    }
    let n = profiles.len();
    let mut v: Vec<(&str, Profile)> = profiles.into_iter().collect();
    // Busiest first, but make sure IPs with successful writes are included.
    v.sort_by(|a, b| b.1.total.cmp(&a.1.total).then(a.0.cmp(b.0)));
    let mut s = String::new();
    for (ip, p) in v.into_iter().take(limit) {
        let ok = p.status.iter().filter(|(c, _)| **c < 400).map(|(_, n)| n).sum::<u64>();
        let status: Vec<String> = p.status.iter().map(|(c, n)| format!("{c}:{n}")).collect();
        let paths = red.text(&top(&p.paths, 8));
        let uas = red.text(&top(&p.uas, 2));
        let _ = writeln!(
            s,
            "{} — {} req ({} <400), {} – {}\n  status {}\n  methods {} · hosts {}\n  paths {} ({} distinct)\n  ua {}",
            red.ip(ip),
            p.total,
            ok,
            p.first.map(|t| t.format("%m-%d %H:%M").to_string()).unwrap_or_default(),
            p.last.map(|t| t.format("%m-%d %H:%M").to_string()).unwrap_or_default(),
            status.join(" "),
            top(&p.methods, 4),
            top(&p.hosts, 3),
            paths,
            p.paths.len(),
            uas
        );
    }
    if n > limit {
        let _ = writeln!(s, "[{} more IPs omitted]", n - limit);
    }
    (s, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::parse(include_str!("../defaults/config.toml"), "defaults".into()).unwrap()
    }

    #[test]
    fn redacts_and_unmasks() {
        let mut r = Redactor::new(&cfg());
        let t = r.text("Failed password for root from 45.1.2.3 port 22; vpn 10.8.1.5; again 45.1.2.3 and 2a02:3030:a1e::3");
        assert_eq!(t, "Failed password for root from ip-1 port 22; vpn vpn-2; again ip-1 and ip-3");
        assert_eq!(r.unmask("ip-1 then ip-3, unknown ip-99"), "45.1.2.3 then 2a02:3030:a1e::3, unknown ip-99");
        let t = r.text("/reset?token=abcdef1234&user=a@b.de&x=1 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x");
        assert!(t.contains("token=<REDACTED>") && t.contains("user=<EMAIL>") && t.contains("Bearer <REDACTED>"), "{t}");
        assert_eq!(r.text("at 14:17:22 version 1.4.6"), "at 14:17:22 version 1.4.6");
        assert_eq!(r.text("Chrome/120.0.0.0 Safari"), "Chrome/120.0.0.0 Safari");
    }

    #[test]
    fn templates_collapse_variables() {
        assert_eq!(template("Started session 4711 for ip-3 id 3f2a9c1b"), "Started session <N> for <IP> id <HEX>");
        assert_eq!(template("/api/user/123/avatar"), "/api/user/<N>/avatar");
    }
}
