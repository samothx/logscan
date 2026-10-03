//! Persistent state between runs: `<state_dir>/state.json`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
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
        opskit::state::load(&dir.join("state.json"))
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        opskit::state::save(&dir.join("state.json"), self)
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
