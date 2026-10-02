use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone};
use clap::{Parser, Subcommand};

use logscan::config::{Config, DEFAULT_CONFIG};
use logscan::model::{Severity, truncate};
use logscan::rules::{RuleSet, TestDef, test_event};
use logscan::scan::{self, Window};
use logscan::state::State;
use logscan::datasets::{Ctx, Redactor};
use logscan::llm::Client;
use logscan::skills::{self, Skill};
use logscan::{mail, notify, report};

/// Daily security review of the journal and nginx access logs: declarative rules + LLM skills.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Config file
    #[arg(long, global = true, value_name = "PATH", default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    /// Override general.state_dir (state.json + reports/)
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan the window since the last run, write the report, push alerts
    Run {
        /// Window start: "24h", "7d", "2026-10-01 00:00" or RFC 3339 (default: last run)
        #[arg(long)]
        since: Option<String>,
        /// Window end (default: now)
        #[arg(long)]
        until: Option<String>,
        /// Skip the LLM skills
        #[arg(long)]
        no_llm: bool,
        /// Don't push, don't store the report, don't update state
        #[arg(long)]
        dry_run: bool,
        /// Print the Markdown report to stdout
        #[arg(long)]
        print: bool,
    },
    /// Inspect and test the rule files
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Inspect, check and try the LLM skills
    Skills {
        #[command(subcommand)]
        cmd: SkillsCmd,
    },
    /// Verify the LLM API key, list models and make a tiny test call
    LlmCheck,
    /// Write a starter config for this host (detects networks, SSH keys, sudo users, ntfy, sendmail)
    Init {
        /// Extra trusted IP or network (repeatable), e.g. another server of yours
        #[arg(long, value_name = "CIDR")]
        trust: Vec<String>,
        /// User whose authorized_keys are approved (repeatable; default: sudo/wheel members)
        #[arg(long, value_name = "USER")]
        ssh_user: Vec<String>,
        /// Mail recipient (repeatable); enables [email] if /usr/sbin/sendmail exists
        #[arg(long, value_name = "ADDR")]
        email_to: Vec<String>,
        /// Mail sender (default: first recipient)
        #[arg(long, value_name = "ADDR")]
        email_from: Option<String>,
        /// File with the "About this host" text for LLM skills
        #[arg(long, value_name = "FILE")]
        host_context: Option<PathBuf>,
        /// Write here instead of stdout; refuses to overwrite an existing file
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Mail a stored report now (regardless of content), using the [email] settings
    Mail {
        /// "latest" or a report file name stem like 2026-10-02_0715
        #[arg(default_value = "latest")]
        which: String,
    },
    /// Print the latest stored report
    Show {
        /// "latest" or a report file name stem like 2026-10-02_0715
        #[arg(default_value = "latest")]
        which: String,
    },
}

#[derive(Subcommand)]
enum SkillsCmd {
    /// List skills
    List,
    /// Load and validate all skill files
    Check,
    /// Scan a window and run one skill (nothing is stored or pushed)
    Run {
        name: String,
        /// Window start (default 24h)
        #[arg(long, default_value = "24h")]
        since: String,
        /// Print the exact prompt and its size instead of calling the API
        #[arg(long)]
        show_prompt: bool,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// List enabled and disabled rules
    List,
    /// Load + compile all rules and run their inline tests
    Check,
    /// Test one rule against a log line
    Test {
        id: String,
        /// nginx: access log line · journal: "ident: message" · file: the line · file_changed: a path
        #[arg(long)]
        line: String,
        /// nginx: treat the client as trusted / untrusted (default: from trusted_networks)
        #[arg(long)]
        trusted: Option<bool>,
        /// journal: priority 0-7
        #[arg(long)]
        priority: Option<u8>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("logscan: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn load_config(cli: &Cli) -> Result<Config> {
    let mut cfg = Config::load(&cli.config)?;
    if let Some(d) = &cli.state_dir {
        cfg.general.state_dir = d.clone();
    }
    Ok(cfg)
}

fn run(cli: Cli) -> Result<ExitCode> {
    if let Cmd::Init { trust, ssh_user, email_to, email_from, host_context, output } = &cli.command {
        let host_context = host_context
            .as_ref()
            .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
            .transpose()?;
        let (text, detected) = logscan::init::generate(&logscan::init::Options {
            trust: trust.clone(),
            ssh_users: ssh_user.clone(),
            email_to: email_to.clone(),
            email_from: email_from.clone(),
            host_context,
        })?;
        match output {
            Some(p) => {
                if p.exists() {
                    bail!("{} exists; not overwriting (remove it or write elsewhere)", p.display());
                }
                std::fs::write(p, &text).with_context(|| format!("writing {}", p.display()))?;
                eprintln!("wrote {}", p.display());
            }
            None => print!("{text}"),
        }
        for n in detected.notes {
            eprintln!("note: {n}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let cfg = load_config(&cli)?;
    match &cli.command {
        Cmd::Run { since, until, no_llm, dry_run, print } => {
            cmd_run(&cfg, since.as_deref(), until.as_deref(), *no_llm, *dry_run, *print)
        }
        Cmd::Init { .. } => unreachable!("handled above"),
        Cmd::Rules { cmd } => cmd_rules(&cfg, cmd),
        Cmd::Skills { cmd } => cmd_skills(&cfg, cmd),
        Cmd::LlmCheck => cmd_llm_check(&cfg),
        Cmd::Mail { which } => {
            let dir = cfg.general.state_dir.join("reports");
            let md_path = dir.join(format!("{which}.md"));
            let md = std::fs::read_to_string(&md_path).with_context(|| format!("reading {}", md_path.display()))?;
            let rep: logscan::model::Report = serde_json::from_slice(
                &std::fs::read(dir.join(format!("{which}.json"))).context("reading the report's .json")?,
            )?;
            if cfg.email.to.is_empty() || cfg.email.from.is_empty() {
                bail!("set email.to and email.from in the config");
            }
            let d = mail::Decision { send: true, reasons: vec!["sent by hand (logscan mail)".into()], fingerprints: Vec::new() };
            let intro = format!("Sent by hand: {}", md_path.display());
            mail::send(&cfg.email, &mail::build_message(&cfg.email, &mail::subject(&rep, &d), &intro, &md))?;
            println!("mailed {} to {}", md_path.display(), cfg.email.to.join(", "));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Show { which } => {
            let p = cfg.general.state_dir.join("reports").join(format!("{which}.md"));
            print!("{}", std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_time(s: &str, now: DateTime<Local>) -> Result<DateTime<Local>> {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now - Duration::hours(h));
    }
    if let Some(d) = s.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now - Duration::days(d));
    }
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Local));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return Local.from_local_datetime(&n).single().ok_or_else(|| anyhow!("ambiguous local time {s}"));
        }
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let n = d.and_hms_opt(0, 0, 0).expect("midnight");
        return Local.from_local_datetime(&n).single().ok_or_else(|| anyhow!("ambiguous local time {s}"));
    }
    bail!("can't parse time '{s}' (24h | 7d | 2026-10-01 | 2026-10-01 07:00 | RFC 3339)")
}

fn cmd_run(cfg: &Config, since: Option<&str>, until: Option<&str>, no_llm: bool, dry_run: bool, print: bool) -> Result<ExitCode> {
    let now = Local::now();
    let state_dir = &cfg.general.state_dir;
    let mut state = match State::load(state_dir) {
        Ok(s) => s,
        Err(e) if dry_run => {
            eprintln!("logscan: {e:#} (dry run: starting from empty state)");
            State::default()
        }
        Err(e) => return Err(e),
    };
    let rules = RuleSet::load_dir(&cfg.rules_dir(), cfg)?;

    let mut win = Window::from_state(cfg, &state, now);
    if let Some(s) = since {
        win.since = parse_time(s, now)?;
    }
    if let Some(u) = until {
        win.until = parse_time(u, now)?;
    }
    if win.since >= win.until {
        bail!("empty window: {} ≥ {}", win.since, win.until);
    }

    let mut result = scan::scan(cfg, &rules, &mut state, &win, true);
    let rule_test_failures = rules.run_tests(cfg);
    for f in rule_test_failures {
        result.report.errors.push(format!("rule test: {f}"));
    }

    if !no_llm && cfg.llm.enabled {
        run_llm(cfg, &mut result, &mut state, &win, now, None);
    }

    let fatal = result.report.errors.iter().any(|e| e.starts_with("journal:"));
    let host = result.report.host.clone();

    if dry_run {
        let alerts: Vec<String> = notify::select_alerts(&mut result.report, &cfg.notify, &state, now.timestamp())
            .iter()
            .map(|f| format!("{} {}", f.severity, f.title))
            .collect();
        if print {
            print!("{}", report::render_markdown(&result.report));
        }
        eprintln!(
            "dry run: {} → {}: {} findings ({} would be pushed), {} errors",
            win.since.format("%Y-%m-%d %H:%M"),
            win.until.format("%Y-%m-%d %H:%M"),
            result.report.findings.len(),
            alerts.len(),
            result.report.errors.len()
        );
        for a in alerts {
            eprintln!("  would push: {}", truncate(&a, 200));
        }
        if cfg.email.enabled {
            let d = mail::decide(&result.report, &cfg.email, &state, now.timestamp());
            if d.send {
                eprintln!("  would email to {}: {}", cfg.email.to.join(", "), d.reasons.join("; "));
            } else {
                eprintln!("  no email: nothing new ≥ {}", cfg.email.min_severity);
            }
        }
        return Ok(if fatal { ExitCode::from(2) } else { ExitCode::SUCCESS });
    }

    let alerts: Vec<logscan::model::Finding> =
        notify::select_alerts(&mut result.report, &cfg.notify, &state, now.timestamp()).into_iter().cloned().collect();
    let path = report::store(&result.report, state_dir)?;
    let path_s = path.display().to_string();
    let markdown = report::render_markdown(&result.report);
    if print {
        print!("{markdown}");
    }

    // Mail the report only when there is something to report.
    let mut mailed_to = None;
    let mut mail_error = None;
    if cfg.email.enabled {
        let d = mail::decide(&result.report, &cfg.email, &state, now.timestamp());
        if d.send {
            let intro = format!("Why this mail: {}.\nReport file on {}: {path_s}", d.reasons.join("; "), host);
            let msg = mail::build_message(&cfg.email, &mail::subject(&result.report, &d), &intro, &markdown);
            match mail::send(&cfg.email, &msg) {
                Ok(()) => {
                    for fp in &d.fingerprints {
                        state.emailed.insert(fp.clone(), now.timestamp());
                    }
                    mailed_to = Some(cfg.email.to.join(", "));
                }
                Err(e) => {
                    eprintln!("logscan: mail failed: {e:#}");
                    mail_error = Some(format!("mail: {e:#}"));
                }
            }
        }
    }
    if let Some(e) = mail_error {
        result.report.errors.push(e);
    }

    if cfg.notify.enabled {
        let mut push_errors = Vec::new();
        if !alerts.is_empty() {
            let refs: Vec<&logscan::model::Finding> = alerts.iter().collect();
            match notify::send(&cfg.notify, &notify::alert_message(&host, &refs, &path_s)) {
                Ok(()) => {
                    for f in &alerts {
                        state.alerted.insert(f.fingerprint.clone(), now.timestamp());
                    }
                }
                Err(e) => push_errors.push(format!("{e:#}")),
            }
        }
        if cfg.notify.digest
            && let Err(e) = notify::send(&cfg.notify, &notify::digest_message(&result.report, &path_s, mailed_to.as_deref()))
        {
            push_errors.push(format!("{e:#}"));
        }
        if !result.report.errors.is_empty() {
            let msg = result.report.errors.iter().map(|e| format!("• {e}")).collect::<Vec<_>>().join("\n");
            let _ = notify::send(&cfg.notify, &notify::error_message(&host, &msg));
        }
        for e in push_errors {
            eprintln!("logscan: push failed: {e}");
        }
    }

    if !fatal {
        state.last_until = Some(win.until);
    }
    let rules_ref = &rules;
    state.prune(now.timestamp(), cfg.notify.repeat_suppress_days, cfg.email.repeat_days, |id| {
        rules_ref.get(id).map(|r| r.remember_days).unwrap_or(90)
    });
    state.save(state_dir)?;
    report::prune(state_dir, cfg.general.report_retention_days);

    eprintln!(
        "logscan: {} findings (max {}), {} alert(s) {}, {}, report {}",
        result.report.findings.len(),
        result.report.max_severity().map(|s| s.to_string()).unwrap_or_else(|| "none".into()),
        alerts.len(),
        if cfg.notify.enabled { "pushed" } else { "(ntfy disabled)" },
        mailed_to.as_deref().map(|t| format!("mailed to {t}")).unwrap_or_else(|| "no mail".into()),
        path_s
    );
    Ok(if fatal { ExitCode::from(2) } else { ExitCode::SUCCESS })
}

fn cmd_rules(cfg: &Config, cmd: &RulesCmd) -> Result<ExitCode> {
    let rules = RuleSet::load_dir(&cfg.rules_dir(), cfg)?;
    match cmd {
        RulesCmd::List => {
            for r in &rules.rules {
                let sev = match r.kind {
                    logscan::rules::Kind::Alert => r.severity.to_string(),
                    logscan::rules::Kind::Stat => "stat".into(),
                    logscan::rules::Kind::Ignore => "ignore".into(),
                };
                println!("{:<36} {:<9} {:<13} {}", r.id, sev, r.source.name(), r.title);
            }
            for (id, file) in &rules.disabled {
                println!("{id:<36} disabled  ({})", file.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        RulesCmd::Check => {
            let fails = rules.run_tests(cfg);
            println!(
                "{} rules ({} disabled), {} inline tests from {}",
                rules.rules.len(),
                rules.disabled.len(),
                rules.test_count(),
                cfg.rules_dir().display()
            );
            for f in &fails {
                println!("FAIL {f}");
            }
            if fails.is_empty() {
                println!("all tests pass");
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        RulesCmd::Test { id, line, trusted, priority } => {
            let rule = rules.get(id).ok_or_else(|| anyhow!("no enabled rule '{id}'"))?;
            let t = TestDef {
                line: Some(line.clone()),
                ident: None,
                message: None,
                priority: *priority,
                kernel: None,
                trusted: *trusted,
                lists: Default::default(),
                expect: true,
            };
            let ev = test_event(rule, &t, cfg)?;
            match rule.match_event(&ev) {
                Some(caps) => {
                    let mut fields: std::collections::BTreeMap<String, String> = logscan::rules::event::known_fields(ev.kind())
                        .iter()
                        .filter_map(|f| ev.get(f).map(|v| (f.to_string(), v.into_owned())))
                        .collect();
                    fields.extend(caps.iter().cloned());
                    println!("MATCH  {}", rule.render_title(&fields));
                    for (k, v) in caps {
                        println!("  {k} = {v}");
                    }
                    if rule.kind == logscan::rules::Kind::Alert && rule.severity >= Severity::High {
                        println!("  (would alert at {})", rule.severity);
                    }
                    Ok(ExitCode::SUCCESS)
                }
                None => {
                    println!("no match");
                    Ok(ExitCode::from(1))
                }
            }
        }
    }
}

/// Runs every enabled, due skill (or only `only`) and merges verdicts + findings into the report.
fn run_llm(cfg: &Config, result: &mut scan::ScanResult, state: &mut State, win: &Window, now: DateTime<Local>, only: Option<&str>) {
    let skills = match skills::load_dir(&cfg.skills_dir(), cfg) {
        Ok(s) => s,
        Err(e) => {
            result.report.errors.push(format!("skills: {e:#}"));
            return;
        }
    };
    let selected: Vec<&Skill> = skills
        .iter()
        .filter(|s| match only {
            Some(n) => s.name == n,
            None => s.enabled && skills::is_due(s, state, now),
        })
        .collect();
    if selected.is_empty() {
        return;
    }
    let client = match Client::new(&cfg.llm) {
        Ok(c) => c,
        Err(e) => {
            result.report.errors.push(format!("llm: {e:#}"));
            return;
        }
    };
    let mut red = Redactor::new(cfg);
    let mut budget = cfg.llm.max_total_chars;
    let mut outcomes = Vec::new();
    let mut errors = Vec::new();
    {
        let ctx = Ctx { events: &result.events, report: &result.report };
        for skill in selected {
            if budget < 2000 {
                errors.push(format!("skill {}: skipped, llm.max_total_chars used up", skill.name));
                continue;
            }
            let prompt = match skills::build_prompt(skill, &ctx, &mut red, &cfg.llm.host_context, win.since, win.until, budget) {
                Ok(p) => p,
                Err(e) => {
                    errors.push(format!("skill {}: {e:#}", skill.name));
                    continue;
                }
            };
            budget = budget.saturating_sub(prompt.data_chars);
            let started = std::time::Instant::now();
            match skills::run_skill(&client, cfg, skill, &prompt, &red) {
                Ok(o) => {
                    eprintln!(
                        "logscan: skill {}: {} ({} findings, {} chars, {:.0?})",
                        skill.name,
                        o.verdict.assessment,
                        o.findings.len(),
                        prompt.user.len(),
                        started.elapsed()
                    );
                    state.skills_last_run.insert(skill.name.clone(), now.timestamp());
                    outcomes.push(o);
                }
                Err(e) => errors.push(format!("skill {}: {e:#}", skill.name)),
            }
        }
    }
    for o in outcomes {
        result.report.llm.push(o.verdict);
        result.report.findings.extend(o.findings);
    }
    result.report.errors.extend(errors);
    result.report.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(&b.rule)));
}

fn cmd_skills(cfg: &Config, cmd: &SkillsCmd) -> Result<ExitCode> {
    let all = skills::load_dir(&cfg.skills_dir(), cfg)?;
    match cmd {
        SkillsCmd::List => {
            for s in &all {
                println!(
                    "{:<20} {:<8} every {}d  max {:<6} {}",
                    s.name,
                    if s.enabled { "enabled" } else { "disabled" },
                    s.every_days,
                    s.max_severity,
                    s.description
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        SkillsCmd::Check => {
            println!("{} skills OK from {}", all.len(), cfg.skills_dir().display());
            for s in &all {
                let ds: Vec<&str> = s.inputs.iter().map(|i| i.def.dataset.as_str()).collect();
                println!("  {} ({}): {}", s.name, s.file.display(), ds.join(", "));
            }
            Ok(ExitCode::SUCCESS)
        }
        SkillsCmd::Run { name, since, show_prompt } => {
            let skill = all.iter().find(|s| s.name == *name).ok_or_else(|| anyhow!("no skill '{name}'"))?;
            let now = Local::now();
            let rules = RuleSet::load_dir(&cfg.rules_dir(), cfg)?;
            let mut state = State::load(&cfg.general.state_dir).unwrap_or_default();
            let win = Window { since: parse_time(since, now)?, until: now };
            let mut result = scan::scan(cfg, &rules, &mut state, &win, true);
            if *show_prompt {
                let mut red = Redactor::new(cfg);
                let ctx = Ctx { events: &result.events, report: &result.report };
                let p = skills::build_prompt(skill, &ctx, &mut red, &cfg.llm.host_context, win.since, win.until, cfg.llm.max_total_chars)?;
                println!("===== SYSTEM =====\n{}\n\n===== USER =====\n{}", p.system, p.user);
                eprintln!(
                    "skill {}: {} chars total ({} data, ≈{} tokens), model {}{}",
                    skill.name,
                    p.system.len() + p.user.len(),
                    p.data_chars,
                    (p.system.len() + p.user.len()) / 4,
                    skill.model,
                    if p.notes.is_empty() { String::new() } else { format!("; {}", p.notes.join("; ")) }
                );
                return Ok(ExitCode::SUCCESS);
            }
            result.report.findings.clear();
            run_llm(cfg, &mut result, &mut state, &win, now, Some(name));
            for v in &result.report.llm {
                println!("{}: {}\n{}\n", v.skill, v.assessment, v.summary);
                if let Some(u) = &v.usage {
                    println!("usage: {u}\n");
                }
            }
            for f in &result.report.findings {
                println!("[{}] {}\n{}", f.severity, f.title, f.detail);
                for e in &f.evidence {
                    println!("  > {}", truncate(e, 300));
                }
                println!();
            }
            for e in &result.report.errors {
                eprintln!("error: {e}");
            }
            Ok(if result.report.llm.is_empty() { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
    }
}

fn cmd_llm_check(cfg: &Config) -> Result<ExitCode> {
    let client = Client::new(&cfg.llm)?;
    println!("provider {} · {} · model {}", cfg.llm.provider, cfg.llm.base_url, cfg.llm.model);
    match client.models() {
        Ok(ids) => {
            let found = ids.contains(&cfg.llm.model);
            println!("{} models available; configured model {}", ids.len(), if found { "FOUND" } else { "NOT in the list" });
            let mut related: Vec<&String> = ids.iter().filter(|m| m.contains("deepseek")).collect();
            related.truncate(20);
            if !related.is_empty() {
                println!("deepseek models: {}", related.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
        }
        Err(e) => println!("listing models failed: {e:#}"),
    }
    let t = std::time::Instant::now();
    let r = client.chat(
        &cfg.llm.model,
        "You answer with a single JSON object.",
        r#"Return exactly {"assessment": "clean", "summary": "ok", "findings": []}"#,
    )?;
    println!("test call OK in {:.1?}: {}", t.elapsed(), truncate(&r.content, 200));
    if let Some(u) = r.usage {
        println!("usage: {u}");
    }
    logscan::llm::parse_verdict(&r.content).context("test answer didn't parse as a verdict")?;
    println!("verdict parsing OK");
    Ok(ExitCode::SUCCESS)
}
