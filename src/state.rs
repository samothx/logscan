//! Persistent state between runs: `<state_dir>/state.json`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// End of the last successful run's window; the next run starts here.
    pub last_until: Option<DateTime<Local>>,
    /// fingerprint → unix time of the last alert push (repeat suppression).
    pub alerted: BTreeMap<String, i64>,
    /// fingerprint → unix time the finding was last included in a mailed report.
    pub emailed: BTreeMap<String, i64>,
    /// rule id → value → unix time last seen (for `new_value_of` rules).
    pub seen: BTreeMap<String, BTreeMap<String, i64>>,
    /// skill name → unix time of the last successful run (for `every_days`).
    pub skills_last_run: BTreeMap<String, i64>,
}

impl State {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("state.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join("state.json");
        let tmp = dir.join("state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Drops entries older than their retention so the file doesn't grow forever.
    pub fn prune(&mut self, now: i64, alert_days: u32, email_days: u32, seen_days: impl Fn(&str) -> u32) {
        self.alerted.retain(|_, t| now - *t < i64::from(alert_days.max(1)) * 86_400);
        self.emailed.retain(|_, t| now - *t < i64::from(email_days.max(1)) * 86_400);
        for (rule, values) in self.seen.iter_mut() {
            let keep = i64::from(seen_days(rule).max(1)) * 86_400;
            values.retain(|_, t| now - *t < keep);
        }
    }
}
