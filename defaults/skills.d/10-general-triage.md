+++
name = "general-triage"
description = "Everything the rules could not classify: unusual journal messages and unmatched web requests"
every_days = 1
max_input_chars = 70000

[[input]]
dataset = "findings"

[[input]]
dataset = "journal.residue"
limit = 400

[[input]]
dataset = "nginx.residue"
limit = 250

[[input]]
dataset = "stats"
limit = 5
+++
Review the journal messages and web requests that no rule recognized, together with what the rules
already found. Look for:

- services crashing, restarting in loops, or logging errors that look like exploitation
  (unexpected child processes, shells, `wget`/`curl` spawned by services, odd cron jobs);
- authentication oddities (new users, logins at unusual times, PAM errors, tokens refused);
- network oddities (new listeners, connections to unusual destinations, DNS errors for strange names);
- containers or services doing things that don't fit their role;
- anything in the rule findings that looks connected to something in the residue.

Routine noise from package updates, backups, timers and the known services is expected.
