//! Runs a RuleSet over a stream of events: grouping, thresholds, correlation, modifiers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Local};

use super::event::{Event, known_fields};
use super::{Caps, Kind, Rule, RuleSet};
use crate::model::{Finding, MAX_EVIDENCE, Severity, StatEntry, truncate};
use crate::state::State;

/// An event plus the strongest rule kind that matched it (None = residue).
pub struct Stored {
    pub ev: Event,
    pub matched: Option<Kind>,
    /// Ids of all rules that matched (for datasets that include matched events).
    pub rules: Vec<u16>,
}

struct Group {
    count: u64,
    first: DateTime<Local>,
    last: DateTime<Local>,
    evidence: Vec<String>,
    /// Fields + captures of the first event.
    fields: BTreeMap<String, String>,
    collected: BTreeMap<String, BTreeSet<String>>,
    /// nginx (host, bytes) pairs seen in this group, for soft404_check.
    sizes: BTreeSet<(String, u64)>,
}

#[derive(Default)]
struct Acc {
    groups: BTreeMap<String, Group>,
    total: u64,
    /// soft404: (host, bytes) → distinct paths
    sizes: HashMap<(String, u64), BTreeSet<String>>,
}

pub struct Engine<'a> {
    set: &'a RuleSet,
    acc: Vec<Acc>,
    /// requires: (target rule idx, `same` fields) → key → count
    req_specs: Vec<(usize, Vec<String>)>,
    req_counts: Vec<HashMap<String, u64>>,
    pub events: Vec<Stored>,
    keep_events: bool,
    /// (host, bytes) of `GET / → 200` answers, for soft404_check.
    homepage_sizes: HashSet<(String, u64)>,
}

pub struct Outcome {
    pub events: Vec<Stored>,
    pub findings: Vec<Finding>,
    pub stats: Vec<StatEntry>,
    pub ignored: u64,
    pub residue: u64,
}

const COLLECT_MAX: usize = 20;
const SOFT404_PATHS: usize = 3;

fn group_key(fields: &[String], ev: &Event, caps: &Caps) -> String {
    if fields.is_empty() {
        return "*".into();
    }
    fields
        .iter()
        .map(|f| super::lookup(ev, caps, f).into_owned())
        .collect::<Vec<_>>()
        .join(" | ")
}

impl<'a> Engine<'a> {
    pub fn new(set: &'a RuleSet, keep_events: bool) -> Self {
        let mut req_specs = Vec::new();
        for r in &set.rules {
            if let Some(req) = &r.requires {
                let idx = set.rules.iter().position(|t| t.id == req.rule).expect("validated at load");
                if !req_specs.iter().any(|(i, s)| *i == idx && *s == req.same) {
                    req_specs.push((idx, req.same.clone()));
                }
            }
        }
        Self {
            set,
            acc: set.rules.iter().map(|_| Acc::default()).collect(),
            req_counts: vec![HashMap::new(); req_specs.len()],
            req_specs,
            events: Vec::new(),
            keep_events,
            homepage_sizes: HashSet::new(),
        }
    }

    pub fn feed(&mut self, ev: Event) {
        if let Event::Nginx(n) = &ev
            && n.path == "/"
            && n.req.status == 200
            && n.req.method == "GET"
            && self.homepage_sizes.len() < 10_000
        {
            self.homepage_sizes.insert((n.req.host.to_ascii_lowercase(), n.req.bytes));
        }
        let mut strongest: Option<Kind> = None;
        let mut matched_rules = Vec::new();
        for (idx, rule) in self.set.rules.iter().enumerate() {
            let Some(caps) = rule.match_event(&ev) else { continue };
            strongest = strongest.max(Some(rule.kind));
            matched_rules.push(idx as u16);
            self.record(idx, rule, &ev, &caps);
            for (si, (target, same)) in self.req_specs.iter().enumerate() {
                if *target == idx {
                    *self.req_counts[si].entry(group_key(same, &ev, &caps)).or_default() += 1;
                }
            }
        }
        if self.keep_events {
            self.events.push(Stored { ev, matched: strongest, rules: matched_rules });
        }
    }

    fn record(&mut self, idx: usize, rule: &Rule, ev: &Event, caps: &Caps) {
        let acc = &mut self.acc[idx];
        acc.total += 1;
        if rule.kind == Kind::Ignore {
            return;
        }
        let key = group_key(&rule.group_by, ev, caps);
        let ts = ev.ts();
        let g = acc.groups.entry(key).or_insert_with(|| {
            let mut fields: BTreeMap<String, String> = known_fields(ev.kind())
                .iter()
                .filter_map(|f| ev.get(f).map(|v| (f.to_string(), v.into_owned())))
                .collect();
            fields.extend(caps.iter().cloned());
            Group {
                count: 0,
                first: ts,
                last: ts,
                evidence: Vec::new(),
                fields,
                collected: BTreeMap::new(),
                sizes: BTreeSet::new(),
            }
        });
        g.count += 1;
        g.first = g.first.min(ts);
        g.last = g.last.max(ts);
        if g.evidence.len() < MAX_EVIDENCE {
            g.evidence.push(truncate(&ev.raw(), 400));
        }
        for f in &rule.collect {
            let set = g.collected.entry(f.clone()).or_default();
            if set.len() < COLLECT_MAX {
                let v = super::lookup(ev, caps, f).into_owned();
                if !v.is_empty() {
                    set.insert(truncate(&v, 160));
                }
            }
        }
        if rule.soft404_check
            && let Event::Nginx(n) = ev
        {
            let k = (n.req.host.to_ascii_lowercase(), n.req.bytes);
            g.sizes.insert(k.clone());
            let paths = acc.sizes.entry(k).or_default();
            if paths.len() < SOFT404_PATHS {
                paths.insert(n.path.clone());
            }
        }
    }

    pub fn finish(mut self, state: &mut State, now: DateTime<Local>, learn_new_values: bool) -> Outcome {
        let events = std::mem::take(&mut self.events);
        let accs = std::mem::take(&mut self.acc);
        let mut findings = Vec::new();
        let mut stats = Vec::new();
        let mut ignored = 0;
        let residue = events.iter().filter(|e| e.matched.is_none()).count() as u64;

        for (rule, acc) in self.set.rules.iter().zip(accs) {
            match rule.kind {
                Kind::Ignore => ignored += acc.total,
                Kind::Stat => {
                    if acc.total == 0 {
                        continue;
                    }
                    let mut top: Vec<(&String, &Group)> =
                        acc.groups.iter().filter(|(_, g)| g.count >= rule.threshold).collect();
                    let groups = top.len() as u64;
                    top.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));
                    stats.push(StatEntry {
                        rule: rule.id.clone(),
                        title: if rule.description.is_empty() { rule.title.clone() } else { rule.description.clone() },
                        total: acc.total,
                        groups,
                        top: top.iter().take(10).map(|(k, g)| format!("{k} ({})", g.count)).collect(),
                    });
                }
                Kind::Alert => {
                    // Catch-all page: one size for ≥3 different matched paths, or exactly the size
                    // of the host's homepage (apps that answer unknown paths with `/`).
                    let catch_all: BTreeSet<&(String, u64)> = acc
                        .sizes
                        .iter()
                        .filter(|(k, paths)| paths.len() >= SOFT404_PATHS || self.homepage_sizes.contains(*k))
                        .map(|(k, _)| k)
                        .collect();
                    // First run of a new_value_of rule only learns (otherwise everything is "new").
                    let learning = learn_new_values && !state.seen.contains_key(&rule.id);
                    if rule.new_value_of.is_some() {
                        state.seen.entry(rule.id.clone()).or_default();
                    }
                    for (key, g) in &acc.groups {
                        if g.count < rule.threshold {
                            continue;
                        }
                        if let Some(req) = &rule.requires {
                            let si = self
                                .req_specs
                                .iter()
                                .position(|(t, s)| self.set.rules[*t].id == req.rule && *s == req.same)
                                .expect("registered in new()");
                            let k = req.same.iter().map(|f| g.fields.get(f).cloned().unwrap_or_default()).collect::<Vec<_>>().join(" | ");
                            if self.req_counts[si].get(&k).copied().unwrap_or(0) < req.min_count {
                                continue;
                            }
                        }
                        if let Some(field) = &rule.new_value_of {
                            let value = g.fields.get(field).cloned().unwrap_or_default();
                            let seen = state.seen.entry(rule.id.clone()).or_default();
                            let known = seen.contains_key(&value);
                            seen.insert(value, now.timestamp());
                            if known || learning {
                                continue;
                            }
                        }
                        let mut severity = rule.severity;
                        let mut title = rule.render_title(&g.fields);
                        if rule.soft404_check && !g.sizes.is_empty() && g.sizes.iter().all(|s| catch_all.contains(s)) {
                            severity = severity.min(Severity::Low);
                            title.push_str(" (same size as a catch-all or home page: probably not the real file)");
                        }
                        let mut detail = if g.count == 1 {
                            format!("1 event at {}", g.first.format("%Y-%m-%d %H:%M:%S"))
                        } else {
                            format!(
                                "{} events, {} – {}",
                                g.count,
                                g.first.format("%Y-%m-%d %H:%M:%S"),
                                g.last.format("%Y-%m-%d %H:%M:%S")
                            )
                        };
                        for (f, vals) in &g.collected {
                            let shown: Vec<&str> = vals.iter().take(10).map(String::as_str).collect();
                            let more = if vals.len() > 10 { format!(" (+{})", vals.len() - 10) } else { String::new() };
                            detail.push_str(&format!("\n{f}: {}{more}", shown.join(", ")));
                        }
                        if !rule.description.is_empty() {
                            detail.push_str(&format!("\n{}", rule.description));
                        }
                        let mut f = Finding::new(&rule.id, severity, title, key).detail(detail).count(g.count);
                        f.evidence = g.evidence.clone();
                        findings.push(f);
                    }
                }
            }
        }
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(&b.rule)));
        Outcome { events, findings, stats, ignored, residue }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::event::NginxEvent;
    use crate::sources::parse_access_line;

    fn cfg() -> Config {
        Config::parse(include_str!("../../defaults/config.toml"), "defaults".into()).unwrap()
    }

    fn nginx(line: &str, cfg: &Config) -> Event {
        let r = parse_access_line(line).unwrap();
        let t = cfg.is_trusted(&r.ip);
        Event::Nginx(NginxEvent::new(r, t))
    }

    fn line(ip: &str, method: &str, path: &str, status: u16, bytes: u64, host: &str) -> String {
        format!(r#"{ip} - - [01/Oct/2026:10:00:00 +0200] "{method} {path} HTTP/1.1" {status} {bytes} "-" "curl/8" sn="{host}""#)
    }

    const RULES: &str = r#"
[[rule]]
id = "wp.fail"
source = "nginx"
kind = "stat"
match = { method = ["POST"], path = '^/wp-login\.php$', status = "200" }
aggregate = { group_by = ["ip"] }

[[rule]]
id = "wp.success_after_bf"
source = "nginx"
severity = "critical"
title = "WP login after brute force from {ip} on {host}"
match = { method = ["POST"], path = '^/wp-login\.php$', status = "302" }
aggregate = { group_by = ["ip", "host"] }
requires = { rule = "wp.fail", same = ["ip"], min_count = 3 }

[[rule]]
id = "secret"
source = "nginx"
severity = "critical"
title = "secret {path} on {host}"
match = { path = '/\.env$', status = "2xx" }
aggregate = { group_by = ["host", "path"] }
soft404_check = true

[[rule]]
id = "noise"
source = "nginx"
kind = "ignore"
match = { trusted = true }
"#;

    fn run(lines: &[String]) -> Outcome {
        let cfg = cfg();
        let set = RuleSet::from_sources(&[("t.toml".into(), RULES.into())], &cfg).unwrap();
        let mut e = Engine::new(&set, true);
        for l in lines {
            e.feed(nginx(l, &cfg));
        }
        e.finish(&mut State::default(), Local::now(), true)
    }

    #[test]
    fn correlation_requires_bruteforce() {
        let mut lines = vec![line("1.1.1.1", "POST", "/wp-login.php", 302, 0, "etnur.net")];
        assert!(run(&lines).findings.is_empty(), "single login must not fire");
        for _ in 0..3 {
            lines.push(line("1.1.1.1", "POST", "/wp-login.php", 200, 4000, "etnur.net"));
        }
        // Another IP's failures must not count.
        lines.push(line("2.2.2.2", "POST", "/wp-login.php", 302, 0, "etnur.net"));
        let out = run(&lines);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].title, "WP login after brute force from 1.1.1.1 on etnur.net");
        assert_eq!(out.stats[0].total, 3);
    }

    #[test]
    fn soft404_downgrades_catch_all() {
        let one = run(&[line("3.3.3.3", "GET", "/.env", 200, 120, "a.de")]);
        assert_eq!(one.findings[0].severity, Severity::Critical);

        // Same size as the host's homepage → the app answered with `/`.
        let home = run(&[
            line("3.3.3.3", "GET", "/", 200, 3207, "fb.de"),
            line("3.3.3.3", "GET", "/.env", 200, 3207, "fb.de"),
        ]);
        assert_eq!(home.findings[0].severity, Severity::Low);

        let spa = run(&[
            line("3.3.3.3", "GET", "/.env", 200, 5000, "spa.de"),
            line("3.3.3.3", "GET", "/api/.env", 200, 5000, "spa.de"),
            line("3.3.3.3", "GET", "/app/.env", 200, 5000, "spa.de"),
        ]);
        assert_eq!(spa.findings.len(), 3);
        assert!(spa.findings.iter().all(|f| f.severity == Severity::Low));
    }

    #[test]
    fn residue_and_ignore() {
        let out = run(&[
            line("10.8.1.5", "GET", "/", 200, 1, "glances.services.etnur.net"),
            line("4.4.4.4", "GET", "/", 200, 1, "etnur.net"),
        ]);
        assert_eq!(out.ignored, 1);
        assert_eq!(out.residue, 1);
    }

    #[test]
    fn new_value_learns_first_then_fires() {
        let cfg = cfg();
        let rules = r#"[[rule]]
id = "ssh.new"
source = "journal"
severity = "low"
title = "new ip {ip}"
match = { message = 'from (?P<ip>\S+)' }
aggregate = { group_by = ["ip"] }
new_value_of = "ip"
"#;
        let set = RuleSet::from_sources(&[("t.toml".into(), rules.into())], &cfg).unwrap();
        let ev = |ip: &str| {
            let t = crate::rules::TestDef {
                line: None, ident: Some("sshd".into()), message: Some(format!("Accepted from {ip}")),
                priority: None, kernel: None, trusted: None, lists: Default::default(), expect: true,
            };
            crate::rules::test_event(&set.rules[0], &t, &cfg).unwrap()
        };
        let mut state = State::default();
        let mut e = Engine::new(&set, false);
        e.feed(ev("1.1.1.1"));
        assert!(e.finish(&mut state, Local::now(), true).findings.is_empty(), "first run learns");
        let mut e = Engine::new(&set, false);
        e.feed(ev("1.1.1.1"));
        e.feed(ev("2.2.2.2"));
        let out = e.finish(&mut state, Local::now(), true);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].title, "new ip 2.2.2.2");
    }
}
