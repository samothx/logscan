# logscan

Daily security review of the systemd journal and nginx access logs for a single server.
It has two layers, and both are plain files you can edit without recompiling:

1. **Rules** (`rules.d/*.toml`): deterministic regex/field checks with grouping, thresholds and
   simple correlation. Fast, explainable, and the only layer you should fully trust.
2. **Skills** (`skills.d/*.md`): focused LLM reviews of what the rules *couldn't* classify, through
   any OpenAI-compatible API (Venice, DeepSeek, …). Optional and advisory.

Findings ≥ `notify.min_severity` are pushed through `ntfy-dispatcher`. A low-priority digest
summarizes every run, and a Markdown + JSON report is kept for 90 days.

```
logscan run   (systemd timer, daily 07:15)
  window = [end of last successful run, now]          first run: 24 h, catch-up cap: 7 d
  sources  journal (journalctl -o json) · nginx access.log/.1/.2.gz · text files (rkhunter,
           chkrootkit) · ctime of watched paths
  rules    alert → findings · stat → digest counters · ignore → known noise
           events no rule matched = "residue"
  skills   each enabled, due skill → one LLM call over its datasets → [AI] findings (≤ high)
  report   /var/lib/logscan/reports/<YYYY-MM-DD_HHMM>.{md,json}, latest.{md,json}
  notify   logscan.alert (≥ high, 7-day repeat suppression) · logscan.digest · logscan.error
  email    the full Markdown report, only when there is something new to report
```

LLM output can only **add** findings. It can't hide or downgrade a rule finding, so a prompt
injection in a log line (attackers choose URLs, user agents and usernames) can't hide an attack.

## CLI

```
logscan [--config /etc/logscan/config.toml] [--state-dir DIR] <command>

run [--since 24h|7d|2026-10-01|RFC3339] [--until …] [--no-llm] [--dry-run] [--print]
rules list | check | test <id> --line '<log line>' [--trusted true|false] [--priority N]
skills list | check | run <name> [--since 24h] [--show-prompt]
llm-check                     # key, model list, test call, verdict parsing
mail [latest|2026-10-02_0715] # mail a stored report now (tests the [email] settings)
show [latest|2026-10-02_0715]
```

Typical tuning loop, as any adm/systemd-journal member (no root needed):

```bash
logscan --state-dir /tmp/ls run --dry-run --no-llm --since 7d --print | less
logscan rules test nginx.secret_exposed --line '1.2.3.4 - - [01/Oct/2026:10:00:00 +0200] "GET /.env HTTP/1.1" 200 812 "-" "curl" sn="x.de"'
logscan skills run web-exploitation --show-prompt | less     # exactly what would be sent
LOGSCAN_API_KEY=… logscan skills run web-exploitation        # one real call, nothing stored
```

Exit codes for `run`: 0 ok · 1 error (config, state, report) · 2 the journal couldn't be read
(report still written, the unit's `OnFailure=` fires).

## Rule language

```toml
[patterns]                              # shared regex fragments, used as {{name}} in any file
web_attack = '''\.\./|<script|…'''

[[rule]]
id       = "ssh.unknown_login"          # unique; prefix of the finding fingerprint
source   = "journal"                    # journal | nginx | file:/abs/path | file_changed
kind     = "alert"                      # alert (default) | stat | ignore
severity = "high"                       # alert only: low | medium | high | critical
title    = "SSH login by {user} from {ip} (key {key})"   # {field} / {capture} placeholders
description = "Shown in the report under the finding."
enabled  = true

[rule.match]                            # all must hold
ident   = ["sshd", "sshd-session"]      # list on a text field = `in`
message = 'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+ \w+(?:: \S+ (?P<key>\S+))?'

[rule.where]                            # all = [...] · any = [...] · none = [...]
any = [ { user = { not_in = "@ssh_users" } }, { key = { not_in = "@ssh_keys" } } ]

[rule.aggregate]
group_by  = ["user", "ip"]              # one finding per group (count, first/last, ≤8 evidence lines)
threshold = 1                           # min events per group

collect = ["ip"]                        # list distinct values in the finding
[[rule.test]]                           # inline tests, run by `rules check`, `run` and the tests
ident = "sshd-session"
message = "Accepted publickey for mallory from 1.2.3.4 port 22 ssh2: ED25519 SHA256:x"
expect = true
```

**Fields** (named regex captures become fields too):

| source | fields |
|---|---|
| `journal` | `ident` (SYSLOG_IDENTIFIER), `unit`, `message` (ANSI stripped), `priority` (0–7), `kernel` |
| `nginx` | `ip`, `method`, `path` (percent-decoded twice, lowercase, no query), `query` (decoded, lowercase), `request` (path?query), `target` (raw), `status`, `bytes`, `host` (lowercase), `ua`, `referer`, `trusted` |
| `file:/path` | `file`, `line` (`[hh:mm:ss] ` prefix stripped), `context` (continuation lines) |
| `file_changed` | `root` (the watched entry from `paths`), `path`, `ctime`, `mtime` |

**Conditions.** Shorthands: a string is a regex (on numeric fields `status`/`bytes`/`priority`: a
range); a list is `in` (numeric: any-of ranges); a bool or integer is equality. Full form:
`{ regex, not_regex, eq, in, not_in, range, not_range, min, max, cidr, not_cidr, ci }`.
- `in`/`not_in` entries may be globs (`*.services.etnur.net`) or `@list` references to `[lists]`
  in config.toml.
- Ranges: `2xx`, `200-299`, `<400`, `>=500`, `404`.
- `cidr`/`not_cidr` test an IP field against networks or `@trusted_networks`.

**Correlation and modifiers**
- `requires = { rule = "nginx.wp_login_failed", same = ["ip"], min_count = 10 }`: the group must also
  have ≥ N hits of another rule (same source; `same` ⊆ `group_by`).
- `soft404_check = true` (nginx): if one host answers ≥3 different matched paths with the same body
  size, it's a catch-all/SPA page, so the finding drops to low.
- `new_value_of = "ip"`, `remember_days = 90`: fire only for values not seen recently. The first run
  only learns.
- `paths = [...]` (file_changed): files or directories (plus their direct children) whose ctime falls
  in the window.

`kind = "ignore"` only removes events from the LLM residue. An event that also matches an alert or
stat rule is still reported.

## Skills

```markdown
+++
name = "web-exploitation"
description = "…"
enabled = true
every_days = 1              # 7 = weekly
model = ""                  # empty: llm.model
max_severity = "high"       # clamped to llm.max_severity
max_input_chars = 80000

[[input]]
dataset = "nginx.rare_success"
limit = 350
host = ["*.converzen.de"]   # optional filters, see below
+++
Instructions for the model …
```

| dataset | content |
|---|---|
| `journal.residue` | journal lines no rule matched, templated + deduped, severe and rare first |
| `journal.filtered` | journal lines filtered by `ident`, `unit`, `message` (regex), `priority_max`; `include_matched` (default true) |
| `nginx.residue` | requests no rule matched (incl. ignore rules), templated by host/method/status class/path |
| `nginx.rare_success` | 2xx answers to untrusted IPs on rarely requested paths (`rare_max`, default 3), no static assets |
| `nginx.ip_profiles` | per untrusted IP: volume, status mix, methods, hosts, top paths, UAs |
| `nginx.filtered` | requests filtered by `host` (globs), `status` (range), `method`, `trusted`, `path` (regex) |
| `findings` / `stats` | this run's rule findings / stat counters |

The system prompt and output schema are fixed. Skills only supply the task text and the data.
Before anything is sent, IPs become stable aliases (`ip-N`, `vpn-N` for trusted networks, mapped
back in the report). E-mails, bearer tokens, long tokens and secret-looking query parameters
(`token=`, `password=`, …) are masked. Each skill's model answer is validated as follows:
- severity is clamped to the skill's cap;
- a finding whose evidence isn't quoted verbatim from the input is downgraded to low;
- the finding's title is prefixed `[AI]` in reports and pushes.

Budget: `max_input_chars` per skill and `llm.max_total_chars` per run. A rough rule is 4 chars ≈ 1 token.

## Configuration

See `defaults/config.toml`. Sections: `[general]` (state dir, rules/skills dirs, retention,
windows), `[lists]` (`trusted_networks` drives nginx `trusted`), `[sources]`, `[notify]`, `[llm]`
(+ `[llm.extra_body]`, merged into every request).

Provider presets:

```toml
# Venice
base_url = "https://api.venice.ai/api/v1"
model = "deepseek-v4-flash"
[llm.extra_body]
venice_parameters = { include_venice_system_prompt = false, strip_thinking_response = true }

# DeepSeek
base_url = "https://api.deepseek.com"
model = "deepseek-flash"
```

## Email

`[email]` mails the report through `sendmail` as multipart/alternative: the Markdown as
text/plain plus an HTML rendering (`html = true`, via pulldown-cmark). Raw HTML in the report
is always escaped, never rendered, because titles and evidence contain attacker-chosen text.
It only sends when there is something to report:
- a finding ≥ `min_severity` (default medium) that wasn't in a mail within `repeat_days` (7);
- an LLM skill whose assessment isn't `clean` (`on_llm_suspicion`);
- errors during the run (`on_errors`).

Quiet days send nothing; the ntfy digest still arrives and says when a report was mailed.
`from` is used as both the envelope sender and the `From:` header. Relays such as Zoho reject
mail whose header doesn't match the account.

## Install

`dist/package.sh` builds `target/bundle/logscan-<ver>-x86_64-linux.tar.gz` (static musl binary,
defaults, units). On anubis the rollout is `~/ai-sysadm/changes/pending/0032-logscan.sh`.

The service runs as system user `logscan` with groups `adm` (nginx logs, rkhunter), `systemd-journal`,
`ntfy-senders` (pushes) and `logscan` (API key file), under a strict sandbox.
