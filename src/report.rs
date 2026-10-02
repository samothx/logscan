//! Report rendering (Markdown + JSON), storage and retention.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{Duration, Local};

use crate::model::{Finding, Origin, Report, Severity};

pub fn render_markdown(r: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# logscan report: {}", r.host);
    let _ = writeln!(
        s,
        "\nWindow: {} → {}  ·  logscan {}\n",
        r.since.format("%Y-%m-%d %H:%M"),
        r.until.format("%Y-%m-%d %H:%M"),
        r.version
    );
    let counts: Vec<String> = Severity::ALL_DESC
        .iter()
        .filter(|s| **s != Severity::Info)
        .map(|sev| format!("{sev}: {}", r.count_at(*sev)))
        .collect();
    let _ = writeln!(s, "**Findings:** {}", counts.join(" · "));
    let _ = writeln!(
        s,
        "**Input:** {} journal entries, {} nginx requests ({} unparsable), {} ignored as noise, {} unmatched (residue)\n",
        r.stats.journal_entries, r.stats.nginx_requests, r.stats.nginx_unparsed, r.stats.ignored_events, r.stats.residue_events
    );

    if !r.errors.is_empty() {
        let _ = writeln!(s, "## Errors\n");
        for e in &r.errors {
            let _ = writeln!(s, "- {e}");
        }
        s.push('\n');
    }

    for v in &r.llm {
        let _ = writeln!(
            s,
            "## LLM skill `{}`: {} ({} / {}, {} chars in)\n\n{}\n",
            v.skill, v.assessment, v.provider, v.model, v.input_chars, v.summary
        );
    }

    if r.findings.is_empty() {
        let _ = writeln!(s, "## Findings\n\nNone.\n");
    }
    for sev in Severity::ALL_DESC {
        let fs: Vec<&Finding> = r.findings.iter().filter(|f| f.severity == sev).collect();
        if fs.is_empty() {
            continue;
        }
        let _ = writeln!(s, "## {} ({})\n", capitalize(&sev.to_string()), fs.len());
        for f in fs {
            let origin = if f.origin == Origin::Llm { " [AI]" } else { "" };
            let repeat = if f.repeat { " _(repeat, not pushed)_" } else { "" };
            let _ = writeln!(s, "### {}{origin}{repeat}\n", f.title);
            let _ = writeln!(s, "`{}` · {} event(s)", f.rule, f.count);
            if !f.detail.is_empty() {
                let _ = writeln!(s, "\n{}", f.detail.trim());
            }
            if !f.evidence.is_empty() {
                let _ = writeln!(s, "\n```");
                for e in &f.evidence {
                    let _ = writeln!(s, "{}", e.replace("```", "'''"));
                }
                let _ = writeln!(s, "```");
            }
            s.push('\n');
        }
    }

    if !r.stats.rules.is_empty() {
        let _ = writeln!(s, "## Statistics\n");
        for st in &r.stats.rules {
            let _ = writeln!(s, "- **{}** (`{}`): {} events, {} groups", st.title, st.rule, st.total, st.groups);
            for t in st.top.iter().take(10) {
                let _ = writeln!(s, "  - {t}");
            }
        }
    }
    s
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// Writes `<dir>/reports/<YYYY-MM-DD_HHMM>.{json,md}` and `latest.{json,md}`. Returns the .md path.
pub fn store(r: &Report, state_dir: &Path) -> Result<PathBuf> {
    let dir = state_dir.join("reports");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let stem = r.until.format("%Y-%m-%d_%H%M").to_string();
    let md = render_markdown(r);
    let json = serde_json::to_vec_pretty(r)?;
    let md_path = dir.join(format!("{stem}.md"));
    for (name, data) in [
        (format!("{stem}.json"), json.as_slice()),
        (format!("{stem}.md"), md.as_bytes()),
        ("latest.json".to_string(), json.as_slice()),
        ("latest.md".to_string(), md.as_bytes()),
    ] {
        let p = dir.join(&name);
        std::fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
    }
    Ok(md_path)
}

/// Deletes dated reports older than `days`. Returns how many files were removed.
pub fn prune(state_dir: &Path, days: u32) -> usize {
    let dir = state_dir.join("reports");
    let cutoff = (Local::now() - Duration::days(i64::from(days.max(1)))).format("%Y-%m-%d").to_string();
    let Ok(rd) = std::fs::read_dir(&dir) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Dated names start with YYYY-MM-DD; string comparison is chronological.
        if name.len() >= 10 && name.as_bytes()[4] == b'-' && name[..10] < *cutoff && std::fs::remove_file(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}
