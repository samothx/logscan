//! `logscan init`: writes a starter config.toml from what the host itself reveals.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde_json::Value;

use crate::config::Config;

pub struct Options {
    /// Extra trusted networks or IPs (e.g. another server of yours).
    pub trust: Vec<String>,
    /// Users whose authorized_keys are read (default: members of sudo/wheel).
    pub ssh_users: Vec<String>,
    pub email_to: Vec<String>,
    pub email_from: Option<String>,
    pub host_context: Option<String>,
}

/// What detection found, for the summary printed by the installer.
pub struct Detected {
    pub notes: Vec<String>,
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn toml_list(items: &[String], indent: &str) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let mut s = String::from("[\n");
    for i in items {
        let _ = writeln!(s, "{indent}  {},", toml_str(i));
    }
    s.push_str(indent);
    s.push(']');
    s
}

fn run_json(args: &[&str]) -> Option<Value> {
    let out = Command::new("ip").args(args).output().ok()?;
    out.status.success().then(|| serde_json::from_slice(&out.stdout).ok()).flatten()
}

/// Trusted networks: loopback; the default-route interface's own addresses (IPv4 /32, IPv6 its
/// global /64); the networks of every other interface (VPN, Docker bridges); Docker's default range.
fn detect_networks(notes: &mut Vec<String>) -> Vec<String> {
    let mut nets: BTreeSet<String> = ["127.0.0.0/8", "::1/128"].iter().map(|s| s.to_string()).collect();
    let mut uplinks = BTreeSet::new();
    for fam in ["-4", "-6"] {
        if let Some(Value::Array(routes)) = run_json(&["-j", fam, "route", "show", "default"]) {
            for r in routes {
                if let Some(d) = r["dev"].as_str() {
                    uplinks.insert(d.to_string());
                }
            }
        }
    }
    let Some(Value::Array(ifaces)) = run_json(&["-j", "addr", "show"]) else {
        notes.push("could not run `ip -j addr`; trusted_networks only has loopback".into());
        return nets.into_iter().collect();
    };
    let mut docker = false;
    for i in ifaces {
        let name = i["ifname"].as_str().unwrap_or("");
        if name == "lo" || name.starts_with("veth") {
            continue;
        }
        docker |= name.starts_with("docker") || name.starts_with("br-");
        for a in i["addr_info"].as_array().into_iter().flatten() {
            if a["scope"].as_str() != Some("global") {
                continue;
            }
            let (Some(local), Some(plen)) = (a["local"].as_str(), a["prefixlen"].as_u64()) else { continue };
            let Ok(addr) = local.parse::<IpAddr>() else { continue };
            let net = if uplinks.contains(name) {
                // Public uplink: only our own address (v4) or our /64 (v6), never the provider's subnet.
                match addr {
                    IpAddr::V4(_) => IpNet::new(addr, 32),
                    IpAddr::V6(_) => IpNet::new(addr, 64.min(plen as u8)),
                }
            } else {
                IpNet::new(addr, plen as u8)
            };
            if let Ok(n) = net {
                nets.insert(n.trunc().to_string());
            }
        }
    }
    if docker {
        nets.insert("172.16.0.0/12".into());
    }
    notes.push(format!("uplink(s): {}", uplinks.into_iter().collect::<Vec<_>>().join(", ")));
    collapse(nets.into_iter().collect())
}

/// Drops networks contained in another listed network (Docker bridges inside 172.16.0.0/12).
fn collapse(nets: Vec<String>) -> Vec<String> {
    let parsed: Vec<IpNet> = nets.iter().filter_map(|n| n.parse().ok()).collect();
    let mut out: Vec<IpNet> = parsed
        .iter()
        .filter(|n| !parsed.iter().any(|o| o != *n && o.contains(*n)))
        .copied()
        .collect();
    out.sort();
    out.dedup();
    out.iter().map(|n| n.to_string()).collect()
}

fn group_members(names: &[&str]) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/etc/group") else { return Vec::new() };
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() == 4 && names.contains(&f[0]) {
            out.extend(f[3].split(',').filter(|s| !s.is_empty()).map(str::to_string));
        }
    }
    out.into_iter().collect()
}

fn home_of(user: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[0] == user).then(|| f[5].to_string())
    })
}

fn key_fingerprints(users: &[String], notes: &mut Vec<String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for u in users {
        let Some(home) = home_of(u) else { continue };
        let ak = format!("{home}/.ssh/authorized_keys");
        match Command::new("ssh-keygen").args(["-lf", &ak]).output() {
            Ok(o) if o.status.success() => {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    if let Some(fp) = line.split_whitespace().nth(1) {
                        out.insert(fp.to_string());
                    }
                }
            }
            _ => notes.push(format!("no readable {ak} (run init as root to include {u}'s keys)")),
        }
    }
    out.into_iter().collect()
}

fn which(cands: &[&str]) -> Option<String> {
    cands.iter().find(|p| Path::new(p).exists()).map(|p| p.to_string())
}

pub fn generate(o: &Options) -> Result<(String, Detected)> {
    let mut notes = Vec::new();
    let host = crate::scan::hostname();

    let mut trusted = detect_networks(&mut notes);
    for t in &o.trust {
        let n = t
            .parse::<IpNet>()
            .or_else(|_| t.parse::<IpAddr>().map(IpNet::from))
            .with_context(|| format!("--trust {t}: not an IP or network"))?;
        trusted.push(n.to_string());
    }
    let trusted = collapse(trusted);

    let sudo_users = group_members(&["sudo", "wheel"]);
    let ssh_users = if o.ssh_users.is_empty() { sudo_users.clone() } else { o.ssh_users.clone() };
    let keys = key_fingerprints(&ssh_users, &mut notes);

    let logs: Vec<String> = ["/var/log/nginx/access.log", "/var/log/nginx/access.log.1", "/var/log/nginx/access.log.2.gz"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match std::fs::read_to_string("/var/log/nginx/access.log") {
        Ok(t) => {
            if t.lines().next().is_some_and(|l| !l.contains(" sn=\"")) {
                notes.push("nginx access.log has no sn=\"$host\" field: host-based rules (vpn_only, write_from_outside, CMS sessions per site) can't tell sites apart. Use log_format vhost_combined (see README).".into());
            }
        }
        Err(_) => notes.push("no readable /var/log/nginx/access.log (nginx rules stay idle)".into()),
    }

    let dispatcher = which(&["/usr/local/bin/ntfy-dispatcher", "/usr/bin/ntfy-dispatcher"]);
    let sendmail = which(&["/usr/sbin/sendmail"]);
    let email_on = !o.email_to.is_empty() && sendmail.is_some();
    if !o.email_to.is_empty() && sendmail.is_none() {
        notes.push("--email-to given but /usr/sbin/sendmail is missing: email disabled".into());
    }
    if dispatcher.is_none() {
        notes.push("ntfy-dispatcher not found: pushes disabled (notify.enabled = false)".into());
    }
    let from = o.email_from.clone().unwrap_or_else(|| o.email_to.first().cloned().unwrap_or_default());
    let context = o.host_context.clone().unwrap_or_else(|| {
        format!("Server {host}. TODO: describe the sites and stacks it runs, who administers it and from where,\nand what traffic is normal. This text is added to every LLM skill prompt.")
    });

    let mut s = String::new();
    let _ = write!(
        s,
        r#"# logscan configuration for {host}, generated by `logscan init`.
# Review the [lists] (they decide what counts as "us"), then `logscan rules check`.
# Reference: README.md (/usr/local/share/doc/logscan/README.md).

[general]
state_dir = "/var/lib/logscan"
rules_dir = "rules.d"
skills_dir = "skills.d"
report_retention_days = 90
default_window_hours = 24
max_window_hours = 168

[lists]
# Loopback, VPN/Docker networks, this host's own addresses (+ --trust extras).
trusted_networks = {trusted}
ssh_users = {ssh_users}
# Approved SSH keys (fingerprints from authorized_keys). A login with any other key → high.
ssh_keys = {keys}
sudo_users = {sudo_users}
priv_groups = ["sudo", "wheel", "root", "adm", "docker", "systemd-journal", "disk", "shadow", "ntfy-senders", "pao-priv-exec", "msmtp"]
# Hosts that must only be reachable from trusted networks (globs allowed).
vpn_only_hosts = []
# Hosts where writes (PUT/POST/PATCH/DELETE 2xx) from outside are reported (e.g. a registry).
write_watch_hosts = []
# App backends with logins: a write from a never-seen IP is reported (low).
admin_hosts = []
# Outbound destinations whose blocked connection attempts are expected (IP or CIDR).
allowed_egress = []
allowed_sensitive_paths = ["/.well-known/*"]

[sources]
journalctl = "/usr/bin/journalctl"
nginx_access_logs = {logs}

[notify]
enabled = {notify_on}
command = {dispatcher}
min_severity = "high"
digest = true
repeat_suppress_days = 7

[email]
enabled = {email_on}
to = {to}
from = {from}
sendmail = "/usr/sbin/sendmail"
min_severity = "medium"
repeat_days = 7
on_llm_suspicion = true
on_errors = true
html = true

[llm]
enabled = false                      # set true once /etc/logscan/llm-api-key exists
provider = "venice"
base_url = "https://api.venice.ai/api/v1"
model = "deepseek-v4-flash"
api_key_file = "/etc/logscan/llm-api-key"
timeout_secs = 300
max_tokens = 8000
max_total_chars = 250000
json_mode = true
pseudonymize_ips = true
max_severity = "high"
host_context = """
{context}
"""

[llm.extra_body]
venice_parameters = {{ include_venice_system_prompt = false, strip_thinking_response = true }}
"#,
        trusted = toml_list(&trusted, ""),
        ssh_users = toml_list(&ssh_users, ""),
        keys = toml_list(&keys, ""),
        sudo_users = toml_list(&sudo_users, ""),
        logs = toml_list(&logs, ""),
        notify_on = dispatcher.is_some(),
        dispatcher = toml_str(dispatcher.as_deref().unwrap_or("/usr/local/bin/ntfy-dispatcher")),
        email_on = email_on,
        to = toml_list(&o.email_to, ""),
        from = toml_str(&from),
        context = context.trim().replace("\"\"\"", "\"\""),
    );
    // Whatever we generate must load.
    Config::parse(&s, "/etc/logscan".into()).context("generated config doesn't parse (bug)")?;
    if keys.is_empty() {
        notes.push("no SSH key fingerprints found: every SSH login will be reported as unknown until ssh_keys is filled".into());
    }
    Ok((s, Detected { notes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_parses() {
        let (s, _) = generate(&Options {
            trust: vec!["159.195.35.234".into(), "2a0a:4cc0:c1:6ea0::/64".into()],
            ssh_users: vec!["nobody-here".into()],
            email_to: vec!["a@example.org".into()],
            email_from: None,
            host_context: Some("Test host \"\"\" with quotes".into()),
        })
        .unwrap();
        let cfg = Config::parse(&s, "/etc/logscan".into()).unwrap();
        assert!(cfg.is_trusted("127.0.0.1"));
        assert!(cfg.is_trusted("159.195.35.234"));
        assert!(cfg.is_trusted("2a0a:4cc0:c1:6ea0::5"));
        assert!(cfg.llm.host_context.contains("Test host"));
    }
}
