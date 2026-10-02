+++
name = "auth-review"
description = "Patterns in logins, sudo use and account changes"
every_days = 1
max_input_chars = 40000

[[input]]
dataset = "findings"

[[input]]
dataset = "journal.filtered"
ident = ["sshd", "sshd-session", "sudo", "su", "pkexec", "polkitd", "useradd", "usermod", "userdel", "groupadd", "gpasswd", "passwd", "chpasswd", "adduser", "crontab", "systemd-logind"]
priority_max = 6
limit = 250

[[input]]
dataset = "stats"
limit = 10
+++
Who administers this host and how (users, where they log in from) is described under "About this
host". Addresses of the owner's own networks appear as `vpn-*`.

Look at logins, sudo usage and account changes as a whole:

- logins at unusual times or from addresses that appear only once, especially if followed by sudo,
  account changes or crontab edits;
- sudo commands that look like an intruder (downloading and running scripts, adding keys or users,
  disabling logging/firewall, reading credential files) rather than routine administration;
- brute force that got further than usual (e.g. a valid username found, or a pre-auth change in pattern);
- account or group changes that weren't accompanied by an obvious admin session.

Routine admin work by the administrators (apt, systemctl, editing configs, running change scripts)
is normal.
