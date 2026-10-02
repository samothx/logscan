//! Declarative rules, loaded from `rules.d/*.toml`. See README.md for the language.

pub mod engine;
pub mod event;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Local;
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;

use crate::config::Config;
use crate::model::Severity;
use crate::sources::{JournalEntry, parse_access_line};
use event::{Event, FileChange, FileLine, NUMERIC_FIELDS, NginxEvent, SourceKind, known_fields};

// ---------------------------------------------------------------------------------------
// File schema
// ---------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    /// Named regex fragments, usable in any rule file as `{{name}}`.
    #[serde(default)]
    patterns: BTreeMap<String, String>,
    #[serde(default)]
    rule: Vec<RuleDef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Known noise: dropped from the LLM residue, nothing reported.
    Ignore,
    /// Counted for the digest/report, never alerted.
    Stat,
    /// Produces findings.
    #[default]
    Alert,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub source: String,
    #[serde(default)]
    pub kind: Kind,
    pub severity: Option<Severity>,
    pub title: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(rename = "match", default)]
    pub matches: BTreeMap<String, CondDef>,
    #[serde(rename = "where", default)]
    pub where_: WhereDef,
    #[serde(default)]
    pub aggregate: AggDef,
    pub requires: Option<RequiresDef>,
    /// nginx: same body size on one host for ≥3 different matched paths → catch-all page, downgrade.
    #[serde(default)]
    pub soft404_check: bool,
    /// Only fire for values of this field not seen in the last `remember_days`.
    pub new_value_of: Option<String>,
    #[serde(default = "d90")]
    pub remember_days: u32,
    /// file_changed: paths to stat (directories: also their direct children).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Distinct values of these fields are listed in the finding.
    #[serde(default)]
    pub collect: Vec<String>,
    #[serde(default)]
    pub test: Vec<TestDef>,
}

fn yes() -> bool {
    true
}
fn d90() -> u32 {
    90
}
fn one() -> u64 {
    1
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhereDef {
    #[serde(default)]
    pub all: Vec<BTreeMap<String, CondDef>>,
    #[serde(default)]
    pub any: Vec<BTreeMap<String, CondDef>>,
    #[serde(default)]
    pub none: Vec<BTreeMap<String, CondDef>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggDef {
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default = "one")]
    pub threshold: u64,
}

impl Default for AggDef {
    fn default() -> Self {
        Self { group_by: Vec::new(), threshold: 1 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiresDef {
    pub rule: String,
    pub same: Vec<String>,
    #[serde(default = "one")]
    pub min_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestDef {
    /// nginx: access log line · journal: "ident: message" · file: the line · file_changed: path
    pub line: Option<String>,
    pub ident: Option<String>,
    pub message: Option<String>,
    pub priority: Option<u8>,
    pub kernel: Option<bool>,
    /// nginx: override the trusted flag computed from `[lists] trusted_networks`.
    pub trusted: Option<bool>,
    pub expect: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CondDef {
    Bool(bool),
    Int(i64),
    /// regex (text fields) or range spec (numeric fields)
    Str(String),
    /// `in` (text fields) or any-of ranges (numeric fields)
    List(Vec<String>),
    Full(Box<FullCond>),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullCond {
    pub regex: Option<String>,
    pub not_regex: Option<String>,
    pub eq: Option<String>,
    #[serde(rename = "in")]
    pub in_: Option<OneOrMany>,
    pub not_in: Option<OneOrMany>,
    pub range: Option<OneOrMany>,
    pub not_range: Option<OneOrMany>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    /// IP address inside one of these networks (plain IPs allowed; "@list" expands).
    pub cidr: Option<OneOrMany>,
    pub not_cidr: Option<OneOrMany>,
    /// Case-insensitive `eq` / `in` / `not_in`.
    #[serde(default)]
    pub ci: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn items(&self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Compiled form
// ---------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct PatSet {
    exact: HashSet<String>,
    globs: Vec<Regex>,
    ci: bool,
}

impl PatSet {
    fn new(items: Vec<String>, ci: bool) -> Result<Self> {
        let mut exact = HashSet::new();
        let mut globs = Vec::new();
        for it in items {
            if it.contains('*') {
                let re = format!(
                    "{}^{}$",
                    if ci { "(?i)" } else { "" },
                    it.split('*').map(regex::escape).collect::<Vec<_>>().join(".*")
                );
                globs.push(Regex::new(&re)?);
            } else {
                exact.insert(if ci { it.to_lowercase() } else { it });
            }
        }
        Ok(Self { exact, globs, ci })
    }

    fn contains(&self, v: &str) -> bool {
        let hit = if self.ci { self.exact.contains(&v.to_lowercase()) } else { self.exact.contains(v) };
        hit || self.globs.iter().any(|g| g.is_match(v))
    }
}

#[derive(Debug)]
pub enum Check {
    Regex(Regex),
    NotRegex(Regex),
    Eq(String, bool),
    In(PatSet),
    NotIn(PatSet),
    Range(Vec<(i64, i64)>),
    NotRange(Vec<(i64, i64)>),
    /// (networks, negate). A value that is not an IP is never inside.
    Cidr(Vec<IpNet>, bool),
}

#[derive(Debug)]
pub struct FieldCond {
    pub field: String,
    pub checks: Vec<Check>,
}

pub type Caps = Vec<(String, String)>;

fn lookup<'a>(ev: &'a Event, caps: &'a Caps, field: &str) -> Cow<'a, str> {
    if let Some((_, v)) = caps.iter().rev().find(|(k, _)| k == field) {
        return Cow::Borrowed(v.as_str());
    }
    ev.get(field).unwrap_or(Cow::Borrowed(""))
}

impl FieldCond {
    fn eval(&self, ev: &Event, caps: &mut Caps) -> bool {
        let v = lookup(ev, caps, &self.field).into_owned();
        for c in &self.checks {
            let ok = match c {
                Check::Regex(re) => match re.captures(&v) {
                    Some(m) => {
                        for name in re.capture_names().flatten() {
                            if let Some(g) = m.name(name) {
                                caps.push((name.to_string(), g.as_str().to_string()));
                            }
                        }
                        true
                    }
                    None => false,
                },
                Check::NotRegex(re) => !re.is_match(&v),
                Check::Eq(want, ci) => {
                    if *ci { v.eq_ignore_ascii_case(want) } else { v == *want }
                }
                Check::In(set) => set.contains(&v),
                Check::NotIn(set) => !set.contains(&v),
                Check::Range(rs) => num(&v).is_some_and(|n| rs.iter().any(|(a, b)| n >= *a && n <= *b)),
                Check::NotRange(rs) => num(&v).is_none_or(|n| !rs.iter().any(|(a, b)| n >= *a && n <= *b)),
                Check::Cidr(nets, negate) => {
                    let inside = v
                        .trim()
                        .parse::<IpAddr>()
                        .is_ok_and(|a| nets.iter().any(|n| n.contains(&a)));
                    inside != *negate
                }
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

fn num(v: &str) -> Option<i64> {
    v.trim().parse().ok()
}

fn eval_all(conds: &[FieldCond], ev: &Event, caps: &mut Caps) -> bool {
    conds.iter().all(|c| c.eval(ev, caps))
}

#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub file: PathBuf,
    pub source: SourceKind,
    /// For `file:<path>` sources.
    pub source_path: Option<PathBuf>,
    pub kind: Kind,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub matches: Vec<FieldCond>,
    pub all: Vec<Vec<FieldCond>>,
    pub any: Vec<Vec<FieldCond>>,
    pub none: Vec<Vec<FieldCond>>,
    pub group_by: Vec<String>,
    pub threshold: u64,
    pub requires: Option<RequiresDef>,
    pub soft404_check: bool,
    pub new_value_of: Option<String>,
    pub remember_days: u32,
    pub paths: Vec<String>,
    pub collect: Vec<String>,
    pub tests: Vec<TestDef>,
}

impl Rule {
    /// Tests match + where. Returns the captures on a match.
    pub fn match_event(&self, ev: &Event) -> Option<Caps> {
        if ev.kind() != self.source {
            return None;
        }
        if let (Some(p), Event::File(f)) = (&self.source_path, ev)
            && Path::new(&f.file) != p
        {
            return None;
        }
        if let Event::FileChanged(c) = ev
            && !self.paths.contains(&c.root)
        {
            return None;
        }
        let mut caps = Caps::new();
        if !eval_all(&self.matches, ev, &mut caps) {
            return None;
        }
        for group in &self.all {
            if !eval_all(group, ev, &mut caps) {
                return None;
            }
        }
        if !self.any.is_empty() {
            // Captures from the first matching alternative are kept.
            let mut hit = false;
            for group in &self.any {
                let mut c = caps.clone();
                if eval_all(group, ev, &mut c) {
                    caps = c;
                    hit = true;
                    break;
                }
            }
            if !hit {
                return None;
            }
        }
        for group in &self.none {
            let mut c = caps.clone();
            if eval_all(group, ev, &mut c) {
                return None;
            }
        }
        Some(caps)
    }

    pub fn render_title(&self, fields: &BTreeMap<String, String>) -> String {
        render_template(&self.title, fields)
    }
}

static PATTERN_REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}").unwrap());

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());

pub fn render_template(t: &str, fields: &BTreeMap<String, String>) -> String {
    PLACEHOLDER
        .replace_all(t, |c: &regex::Captures| {
            fields
                .get(&c[1])
                .filter(|v| !v.is_empty())
                .map(|v| crate::model::truncate(v, 120))
                .unwrap_or_else(|| "?".into())
        })
        .into_owned()
}

// ---------------------------------------------------------------------------------------
// Loading + compiling
// ---------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// Rules with `enabled = false` (listed, not evaluated).
    pub disabled: Vec<(String, PathBuf)>,
}

impl RuleSet {
    pub fn load_dir(dir: &Path, cfg: &Config) -> Result<Self> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("reading rules dir {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .collect();
        files.sort();
        let mut sources = Vec::new();
        for f in files {
            let text = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
            sources.push((f, text));
        }
        Self::from_sources(&sources, cfg)
    }

    pub fn from_sources(files: &[(PathBuf, String)], cfg: &Config) -> Result<Self> {
        let mut set = RuleSet::default();
        let mut seen = HashSet::new();
        let mut parsed = Vec::new();
        let mut patterns = BTreeMap::new();
        for (path, text) in files {
            let rf: RuleFile = toml::from_str(text).with_context(|| format!("parsing {}", path.display()))?;
            for (name, re) in &rf.patterns {
                if patterns.insert(name.clone(), re.clone()).is_some() {
                    bail!("{}: duplicate pattern '{name}'", path.display());
                }
            }
            parsed.push((path, rf));
        }
        for (path, rf) in parsed {
            for def in rf.rule {
                if !seen.insert(def.id.clone()) {
                    bail!("{}: duplicate rule id '{}'", path.display(), def.id);
                }
                if !def.enabled {
                    set.disabled.push((def.id.clone(), path.clone()));
                    continue;
                }
                let id = def.id.clone();
                let rule = compile(def, path, cfg, &patterns).with_context(|| format!("{}: rule '{id}'", path.display()))?;
                set.rules.push(rule);
            }
        }
        // Cross-rule references.
        for r in &set.rules {
            if let Some(req) = &r.requires {
                let target = set
                    .rules
                    .iter()
                    .find(|t| t.id == req.rule)
                    .ok_or_else(|| anyhow!("rule '{}': requires unknown or disabled rule '{}'", r.id, req.rule))?;
                if target.source != r.source {
                    bail!("rule '{}': requires '{}' from a different source", r.id, req.rule);
                }
            }
        }
        Ok(set)
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Runs every rule's inline `[[rule.test]]` cases. Returns one message per failure.
    pub fn run_tests(&self, cfg: &Config) -> Vec<String> {
        let mut fails = Vec::new();
        for r in &self.rules {
            for (i, t) in r.tests.iter().enumerate() {
                match test_event(r, t, cfg) {
                    Ok(ev) => {
                        let got = r.match_event(&ev).is_some();
                        if got != t.expect {
                            fails.push(format!(
                                "{} test #{}: expected {}, got {} — {}",
                                r.id,
                                i + 1,
                                if t.expect { "match" } else { "no match" },
                                if got { "match" } else { "no match" },
                                crate::model::truncate(&ev.raw(), 200)
                            ));
                        }
                    }
                    Err(e) => fails.push(format!("{} test #{}: {e:#}", r.id, i + 1)),
                }
            }
        }
        fails
    }

    pub fn test_count(&self) -> usize {
        self.rules.iter().map(|r| r.tests.len()).sum()
    }
}

/// Builds an event for a rule from a test case or a `rules test --line` argument.
pub fn test_event(rule: &Rule, t: &TestDef, cfg: &Config) -> Result<Event> {
    let now = Local::now();
    Ok(match rule.source {
        SourceKind::Nginx => {
            let line = t.line.as_deref().ok_or_else(|| anyhow!("nginx test needs `line`"))?;
            let req = parse_access_line(line).ok_or_else(|| anyhow!("not a vhost_combined line: {line}"))?;
            let trusted = t.trusted.unwrap_or_else(|| cfg.is_trusted(&req.ip));
            Event::Nginx(NginxEvent::new(req, trusted))
        }
        SourceKind::Journal => {
            let (ident, message) = match (&t.ident, &t.message, &t.line) {
                (_, Some(m), _) => (t.ident.clone().unwrap_or_default(), m.clone()),
                (_, None, Some(l)) => match l.split_once(": ") {
                    Some((i, m)) => (i.to_string(), m.to_string()),
                    None => (String::new(), l.clone()),
                },
                _ => bail!("journal test needs `message` or `line`"),
            };
            let kernel = t.kernel.unwrap_or(ident == "kernel");
            Event::Journal(JournalEntry {
                ts: now,
                priority: t.priority.unwrap_or(6),
                ident,
                unit: String::new(),
                kernel,
                message,
            })
        }
        SourceKind::File => Event::File(FileLine {
            file: rule
                .source_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            line: t.line.clone().ok_or_else(|| anyhow!("file test needs `line`"))?,
            context: Vec::new(),
            ts: now,
        }),
        SourceKind::FileChanged => Event::FileChanged({
            let path = t.line.clone().ok_or_else(|| anyhow!("file_changed test needs `line` (a path)"))?;
            // The longest watched path that contains it, as the scanner would compute.
            let root = rule
                .paths
                .iter()
                .filter(|p| path == **p || path.starts_with(&format!("{}/", p.trim_end_matches('/'))))
                .max_by_key(|p| p.len())
                .cloned()
                .unwrap_or_default();
            FileChange {
                root,
                path,
                ctime: now,
                mtime: now,
            }
        }),
    })
}

fn parse_source(s: &str) -> Result<(SourceKind, Option<PathBuf>)> {
    Ok(match s {
        "journal" => (SourceKind::Journal, None),
        "nginx" => (SourceKind::Nginx, None),
        "file_changed" => (SourceKind::FileChanged, None),
        _ => match s.strip_prefix("file:") {
            Some(p) if p.starts_with('/') => (SourceKind::File, Some(PathBuf::from(p))),
            _ => bail!("unknown source '{s}' (journal | nginx | file:/abs/path | file_changed)"),
        },
    })
}

fn compile(def: RuleDef, file: &Path, cfg: &Config, patterns: &BTreeMap<String, String>) -> Result<Rule> {
    let (source, source_path) = parse_source(&def.source)?;
    let severity = match (def.kind, def.severity) {
        (Kind::Alert, Some(s)) => s,
        (Kind::Alert, None) => bail!("alert rules need a severity"),
        (_, s) => s.unwrap_or(Severity::Info),
    };
    if source == SourceKind::FileChanged && def.paths.is_empty() {
        bail!("file_changed rules need `paths`");
    }

    let ctx = Ctx { cfg, source, patterns };
    let matches = ctx.conds(&def.matches)?;
    let groups = |v: &Vec<BTreeMap<String, CondDef>>| v.iter().map(|m| ctx.conds(m)).collect::<Result<Vec<_>>>();
    let all = groups(&def.where_.all)?;
    let any = groups(&def.where_.any)?;
    let none = groups(&def.where_.none)?;

    // Everything that names a field must name a real one (source field or regex capture).
    let mut names: BTreeSet<String> = known_fields(source).iter().map(|s| s.to_string()).collect();
    for c in matches.iter().chain(all.iter().flatten()).chain(any.iter().flatten()).chain(none.iter().flatten()) {
        for ch in &c.checks {
            if let Check::Regex(re) = ch {
                names.extend(re.capture_names().flatten().map(str::to_string));
            }
        }
    }
    let check_field = |what: &str, f: &str| -> Result<()> {
        if names.contains(f) {
            Ok(())
        } else {
            bail!("{what} references unknown field '{f}' (fields: {})", names.iter().cloned().collect::<Vec<_>>().join(", "))
        }
    };
    for c in matches.iter().chain(all.iter().flatten()).chain(any.iter().flatten()).chain(none.iter().flatten()) {
        check_field("condition", &c.field)?;
    }
    for f in &def.aggregate.group_by {
        check_field("group_by", f)?;
    }
    for f in &def.collect {
        check_field("collect", f)?;
    }
    if let Some(f) = &def.new_value_of {
        check_field("new_value_of", f)?;
    }
    if let Some(req) = &def.requires {
        for f in &req.same {
            if !def.aggregate.group_by.contains(f) {
                bail!("requires.same field '{f}' must also be in aggregate.group_by");
            }
        }
    }
    let title = def.title.clone().unwrap_or_else(|| def.id.clone());
    for c in PLACEHOLDER.captures_iter(&title) {
        check_field("title", &c[1])?;
    }
    if def.soft404_check && source != SourceKind::Nginx {
        bail!("soft404_check only applies to nginx rules");
    }

    Ok(Rule {
        id: def.id,
        file: file.to_path_buf(),
        source,
        source_path,
        kind: def.kind,
        severity,
        title,
        description: def.description,
        matches,
        all,
        any,
        none,
        group_by: def.aggregate.group_by,
        threshold: def.aggregate.threshold.max(1),
        requires: def.requires,
        soft404_check: def.soft404_check,
        new_value_of: def.new_value_of,
        remember_days: def.remember_days,
        paths: def.paths,
        collect: def.collect,
        tests: def.test,
    })
}

struct Ctx<'a> {
    cfg: &'a Config,
    source: SourceKind,
    patterns: &'a BTreeMap<String, String>,
}

impl Ctx<'_> {
    fn conds(&self, m: &BTreeMap<String, CondDef>) -> Result<Vec<FieldCond>> {
        m.iter()
            .map(|(field, def)| {
                Ok(FieldCond {
                    field: field.clone(),
                    checks: self.checks(field, def).with_context(|| format!("field '{field}'"))?,
                })
            })
            .collect()
    }

    /// Compiles a regex after substituting `{{name}}` pattern references.
    fn re(&self, s: &str) -> Result<Regex> {
        let mut err = None;
        let expanded = PATTERN_REF.replace_all(s, |c: &regex::Captures| match self.patterns.get(&c[1]) {
            Some(p) => format!("(?:{p})"),
            None => {
                err = Some(c[1].to_string());
                String::new()
            }
        });
        if let Some(name) = err {
            bail!("unknown pattern '{{{{{name}}}}}' (define it under [patterns])");
        }
        Ok(Regex::new(&expanded)?)
    }

    fn cidrs(&self, l: &OneOrMany) -> Result<Vec<IpNet>> {
        self.expand(&l.items())?
            .iter()
            .map(|s| {
                s.parse::<IpNet>()
                    .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| anyhow!("not a network or IP: {s:?}"))
            })
            .collect()
    }

    fn numeric(&self, field: &str) -> bool {
        NUMERIC_FIELDS.contains(&field) && known_fields(self.source).contains(&field)
    }

    fn checks(&self, field: &str, def: &CondDef) -> Result<Vec<Check>> {
        let numeric = self.numeric(field);
        Ok(match def {
            CondDef::Bool(b) => vec![Check::Eq(b.to_string(), false)],
            CondDef::Int(n) => vec![Check::Range(vec![(*n, *n)])],
            CondDef::Str(s) if numeric => vec![Check::Range(vec![parse_range(s)?])],
            CondDef::Str(s) => vec![Check::Regex(self.re(s)?)],
            CondDef::List(v) if numeric => vec![Check::Range(v.iter().map(|s| parse_range(s)).collect::<Result<_>>()?)],
            CondDef::List(v) => vec![Check::In(PatSet::new(self.expand(v)?, false)?)],
            CondDef::Full(f) => {
                let mut out = Vec::new();
                if let Some(r) = &f.regex {
                    out.push(Check::Regex(self.re(r)?));
                }
                if let Some(r) = &f.not_regex {
                    out.push(Check::NotRegex(self.re(r)?));
                }
                if let Some(e) = &f.eq {
                    out.push(Check::Eq(e.clone(), f.ci));
                }
                if let Some(l) = &f.in_ {
                    out.push(Check::In(PatSet::new(self.expand(&l.items())?, f.ci)?));
                }
                if let Some(l) = &f.not_in {
                    out.push(Check::NotIn(PatSet::new(self.expand(&l.items())?, f.ci)?));
                }
                if let Some(r) = &f.range {
                    out.push(Check::Range(r.items().iter().map(|s| parse_range(s)).collect::<Result<_>>()?));
                }
                if let Some(r) = &f.not_range {
                    out.push(Check::NotRange(r.items().iter().map(|s| parse_range(s)).collect::<Result<_>>()?));
                }
                if let Some(l) = &f.cidr {
                    out.push(Check::Cidr(self.cidrs(l)?, false));
                }
                if let Some(l) = &f.not_cidr {
                    out.push(Check::Cidr(self.cidrs(l)?, true));
                }
                if f.min.is_some() || f.max.is_some() {
                    out.push(Check::Range(vec![(f.min.unwrap_or(i64::MIN), f.max.unwrap_or(i64::MAX))]));
                }
                if out.is_empty() {
                    bail!("empty condition");
                }
                out
            }
        })
    }

    /// Expands "@name" entries from `[lists]`.
    fn expand(&self, items: &[String]) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for it in items {
            match it.strip_prefix('@') {
                Some(name) => out.extend(
                    self.cfg
                        .lists
                        .get(name)
                        .ok_or_else(|| anyhow!("unknown list '@{name}' (define it under [lists])"))?
                        .iter()
                        .cloned(),
                ),
                None => out.push(it.clone()),
            }
        }
        Ok(out)
    }
}

/// "2xx", "200-299", "<400", "<=399", ">=500", ">499", "404"
pub fn parse_range(s: &str) -> Result<(i64, i64)> {
    let s = s.trim();
    let bad = || anyhow!("bad range '{s}' (2xx | 200-299 | <400 | >=500 | 404)");
    if let Some(d) = s.strip_suffix("xx")
        && d.len() == 1
    {
        let d: i64 = d.parse().map_err(|_| bad())?;
        return Ok((d * 100, d * 100 + 99));
    }
    if let Some(r) = s.strip_prefix("<=") {
        return Ok((i64::MIN, r.parse().map_err(|_| bad())?));
    }
    if let Some(r) = s.strip_prefix(">=") {
        return Ok((r.parse().map_err(|_| bad())?, i64::MAX));
    }
    if let Some(r) = s.strip_prefix('<') {
        return Ok((i64::MIN, r.parse::<i64>().map_err(|_| bad())? - 1));
    }
    if let Some(r) = s.strip_prefix('>') {
        return Ok((r.parse::<i64>().map_err(|_| bad())? + 1, i64::MAX));
    }
    if let Some((a, b)) = s.split_once('-') {
        return Ok((a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?));
    }
    let n = s.parse().map_err(|_| bad())?;
    Ok((n, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::parse(include_str!("../../defaults/config.toml"), "defaults".into()).unwrap()
    }

    fn set(text: &str) -> Result<RuleSet> {
        RuleSet::from_sources(&[("t.toml".into(), text.to_string())], &cfg())
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("2xx").unwrap(), (200, 299));
        assert_eq!(parse_range("<400").unwrap(), (i64::MIN, 399));
        assert_eq!(parse_range(">=500").unwrap(), (500, i64::MAX));
        assert_eq!(parse_range("200-206").unwrap(), (200, 206));
        assert!(parse_range("abc").is_err());
    }

    #[test]
    fn default_rules_load_and_pass_their_tests() {
        let cfg = cfg();
        let rs = RuleSet::load_dir(&cfg.rules_dir(), &cfg).unwrap();
        assert!(rs.rules.len() > 20, "only {} rules", rs.rules.len());
        assert!(rs.test_count() > 40, "only {} tests", rs.test_count());
        let fails = rs.run_tests(&cfg);
        assert!(fails.is_empty(), "rule tests failed:\n{}", fails.join("\n"));
    }

    #[test]
    fn rejects_unknown_field_and_list() {
        let e = set(r#"[[rule]]
id = "x"
source = "journal"
severity = "low"
match = { messag = "x" }"#)
        .unwrap_err();
        assert!(format!("{e:#}").contains("unknown field 'messag'"), "{e:#}");

        let e = set(r#"[[rule]]
id = "x"
source = "journal"
severity = "low"
match = { ident = ["@nope"] }"#)
        .unwrap_err();
        assert!(format!("{e:#}").contains("unknown list '@nope'"), "{e:#}");
    }

    #[test]
    fn rejects_bad_regex_and_duplicates() {
        assert!(set("[[rule]]\nid='x'\nsource='journal'\nseverity='low'\nmatch={message='('}").is_err());
        let dup = "[[rule]]\nid='x'\nsource='journal'\nkind='stat'\n[[rule]]\nid='x'\nsource='journal'\nkind='stat'\n";
        assert!(format!("{:#}", set(dup).unwrap_err()).contains("duplicate"));
    }

    #[test]
    fn captures_feed_where_and_title() {
        let rs = set(r#"[[rule]]
id = "ssh.t"
source = "journal"
severity = "high"
title = "login {user} from {ip}"
match = { ident = ["sshd"], message = 'Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)' }
where = { any = [ { user = { not_in = "@ssh_users" } } ] }
"#)
        .unwrap();
        let r = &rs.rules[0];
        let mk = |m: &str| test_event(r, &TestDef {
            line: None, ident: Some("sshd".into()), message: Some(m.into()),
            priority: None, kernel: None, trusted: None, expect: true,
        }, &cfg()).unwrap();
        assert!(r.match_event(&mk("Accepted publickey for thomas from 1.2.3.4 port 1 ssh2")).is_none());
        let caps = r.match_event(&mk("Accepted publickey for mallory from 1.2.3.4 port 1 ssh2")).unwrap();
        let fields: BTreeMap<_, _> = caps.into_iter().collect();
        assert_eq!(r.render_title(&fields), "login mallory from 1.2.3.4");
    }

    #[test]
    fn globs_in_lists() {
        let p = PatSet::new(vec!["*.services.etnur.net".into(), "x".into()], true).unwrap();
        assert!(p.contains("n8n.services.etnur.net"));
        assert!(!p.contains("services.etnur.net"));
        assert!(p.contains("X"));
    }
}
