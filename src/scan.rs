//! One scan: read sources for the window, run the rules, return a Report plus the kept events.

use chrono::{DateTime, Duration, Local};

use crate::config::Config;
use crate::model::{Report, Stats};
use crate::rules::engine::{Engine, Stored};
use crate::rules::event::{Event, FileChange, FileLine, NginxEvent, SourceKind};
use crate::rules::RuleSet;
use crate::sources;
use crate::state::State;

pub struct Window {
    pub since: DateTime<Local>,
    pub until: DateTime<Local>,
}

impl Window {
    /// From the last successful run (or the default window), capped at max_window_hours.
    pub fn from_state(cfg: &Config, state: &State, now: DateTime<Local>) -> Self {
        let default = now - Duration::hours(i64::from(cfg.general.default_window_hours));
        let cap = now - Duration::hours(i64::from(cfg.general.max_window_hours));
        let since = state.last_until.unwrap_or(default).max(cap).min(now);
        Self { since, until: now }
    }
}

pub struct ScanResult {
    pub report: Report,
    /// Journal + nginx events with their match status, for the LLM datasets.
    pub events: Vec<Stored>,
}

pub fn scan(cfg: &Config, rules: &RuleSet, state: &mut State, win: &Window, learn: bool) -> ScanResult {
    let mut errors = Vec::new();
    let mut stats = Stats::default();
    let mut engine = Engine::new(rules, true);

    // journal
    match sources::read_journal(&cfg.sources.journalctl, win.since, win.until, |e| engine.feed(Event::Journal(e))) {
        Ok(n) => stats.journal_entries = n,
        Err(e) => errors.push(format!("journal: {e:#}")),
    }

    // nginx
    let mut reqs = Vec::new();
    for path in &cfg.sources.nginx_access_logs {
        if !path.exists() {
            continue;
        }
        match sources::read_access_log(path, win.since, win.until, &mut reqs) {
            Ok(bad) => stats.nginx_unparsed += bad,
            Err(e) => errors.push(format!("{}: {e:#}", path.display())),
        }
    }
    // Rotation can leave the same line in two files only in theory; order doesn't matter for rules.
    reqs.sort_by_key(|r| r.ts);
    stats.nginx_requests = reqs.len() as u64;
    for r in reqs {
        let trusted = cfg.is_trusted(&r.ip);
        engine.feed(Event::Nginx(NginxEvent::new(r, trusted)));
    }

    // file:<path> sources (each file once, whatever number of rules use it)
    let mut files: Vec<&std::path::Path> = rules
        .rules
        .iter()
        .filter_map(|r| r.source_path.as_deref())
        .collect();
    files.sort();
    files.dedup();
    for f in files {
        match sources::read_text_file(f, win.since) {
            Ok(Some((mtime, lines))) => {
                for l in lines {
                    // Dated lines (dpkg.log) are windowed individually; undated reports
                    // (rkhunter, chkrootkit) count as a whole when the file changed in the window.
                    if let Some(t) = l.ts
                        && (t < win.since || t >= win.until)
                    {
                        continue;
                    }
                    engine.feed(Event::File(FileLine {
                        file: f.display().to_string(),
                        line: l.line,
                        context: l.context,
                        ts: l.ts.unwrap_or(mtime),
                    }));
                }
            }
            Ok(None) => {}
            Err(e) => errors.push(format!("{e:#}")),
        }
    }

    // file_changed: every rule stats its own paths
    let mut all_paths: Vec<String> = rules
        .rules
        .iter()
        .filter(|r| r.source == SourceKind::FileChanged)
        .flat_map(|r| r.paths.iter().cloned())
        .collect();
    all_paths.sort();
    all_paths.dedup();
    let (changed, errs) = sources::changed_paths(&all_paths, win.since, win.until);
    errors.extend(errs);
    for c in changed {
        // Attribute the change to the longest watched path containing it; rules match on `root`.
        let root = all_paths
            .iter()
            .filter(|p| c.path == **p || c.path.starts_with(&format!("{}/", p.trim_end_matches('/'))))
            .max_by_key(|p| p.len())
            .cloned()
            .unwrap_or_else(|| c.path.clone());
        engine.feed(Event::FileChanged(FileChange { root, path: c.path, ctime: c.ctime, mtime: c.mtime }));
    }

    let out = engine.finish(state, win.until, learn);
    stats.rules = out.stats;
    stats.ignored_events = out.ignored;
    stats.residue_events = out.residue;

    ScanResult {
        report: Report {
            host: hostname(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            since: win.since,
            until: win.until,
            findings: out.findings,
            stats,
            llm: Vec::new(),
            errors,
        },
        events: out.events,
    }
}

pub fn hostname() -> String {
    opskit::hostname()
}
