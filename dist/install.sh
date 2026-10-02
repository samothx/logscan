#!/usr/bin/env bash
#
# install.sh: install or upgrade logscan on a host. Idempotent; run as root from an unpacked
# bundle (dist/package.sh):
#
#   sudo ./install.sh [options]
#
# Options:
#   --trust CIDR          extra trusted IP/network for a new config (repeatable)
#   --ssh-user USER       user whose authorized_keys are approved (repeatable; default sudo members)
#   --email-to ADDR       mail reports here (repeatable; needs /usr/sbin/sendmail)
#   --email-from ADDR     sender address the mail relay accepts (default: first --email-to)
#   --host-context FILE   "About this host" text for the LLM skills
#   --local-rules FILE    extra host-specific rule file for rules.d (repeatable)
#   --no-first-run        don't run logscan once at the end (still enables the timer)
#   --bin PATH            binary to install (default: ./logscan from the bundle)
#
# A new /etc/logscan/config.toml is generated with `logscan init` from the host itself. An existing
# config, and locally edited rules/skills, are never overwritten: the shipped version is written
# next to them as *.new.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root: sudo $0" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
ETC=/etc/logscan
UNITS=/etc/systemd/system
DISPATCH_CFG=/etc/ntfy-dispatcher/config.toml
BIN="$HERE/logscan"
FIRST_RUN=1
INIT_ARGS=()
LOCAL_RULES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --trust|--ssh-user|--email-to|--email-from|--host-context)
      [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 1; }
      INIT_ARGS+=("$1" "$2"); shift 2 ;;
    --local-rules) LOCAL_RULES+=("$2"); shift 2 ;;
    --no-first-run) FIRST_RUN=0; shift ;;
    --bin) BIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }
for d in "$HERE/defaults/rules.d" "$HERE/defaults/skills.d" "$HERE/systemd"; do
  [ -d "$d" ] || { echo "bundle incomplete: missing $d" >&2; exit 1; }
done

backup() { [ -e "$1" ] && cp -a "$1" "$1.orig-$STAMP" && echo "  backup: $1.orig-$STAMP"; return 0; }

# install_keep SRC DST: install a config file, never overwriting local edits.
install_keep() {
  if [ ! -e "$2" ]; then
    install -o root -g root -m 0644 "$1" "$2"; echo "  installed $2"
  elif cmp -s "$1" "$2"; then
    echo "  unchanged $2"
  else
    install -o root -g root -m 0644 "$1" "$2.new"
    echo "  KEPT local $2 (shipped version: $2.new — diff and merge by hand)"
  fi
}

echo "=== logscan install on $(hostname) ($("$BIN" --version)) ==="

# --- user + groups --------------------------------------------------------------------
if ! id logscan >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/logscan --no-create-home \
          --shell /usr/sbin/nologin --comment "logscan security log review" logscan
  echo "  created system user logscan"
fi
GROUPS_PRESENT=()
for g in adm systemd-journal ntfy-senders msmtp; do
  getent group "$g" >/dev/null && GROUPS_PRESENT+=("$g")
done
usermod -aG "$(IFS=,; echo "${GROUPS_PRESENT[*]}")" logscan
echo "  logscan groups: $(id -nG logscan)"

# --- binary + docs ----------------------------------------------------------------------
backup /usr/local/bin/logscan
install -o root -g root -m 0755 "$BIN" /usr/local/bin/logscan
if [ -f "$HERE/README.md" ]; then
  install -d -m 0755 /usr/local/share/doc/logscan
  install -m 0644 "$HERE/README.md" /usr/local/share/doc/logscan/README.md
fi

# --- config, rules, skills ----------------------------------------------------------------
install -d -o root -g root -m 0755 "$ETC" "$ETC/rules.d" "$ETC/skills.d"
for f in "$HERE"/defaults/rules.d/*.toml; do install_keep "$f" "$ETC/rules.d/$(basename "$f")"; done
for f in "$HERE"/defaults/skills.d/*.md;  do install_keep "$f" "$ETC/skills.d/$(basename "$f")"; done
for f in "${LOCAL_RULES[@]}"; do install_keep "$f" "$ETC/rules.d/$(basename "$f")"; done
if [ -e "$ETC/config.toml" ]; then
  echo "  kept existing $ETC/config.toml (\`logscan init\` prints a fresh one for comparison)"
else
  /usr/local/bin/logscan init "${INIT_ARGS[@]}" --output "$ETC/config.toml"
  chmod 0644 "$ETC/config.toml"
fi
if [ -e "$ETC/llm-api-key" ]; then
  chown root:logscan "$ETC/llm-api-key"; chmod 0640 "$ETC/llm-api-key"
  echo "  $ETC/llm-api-key present (root:logscan 0640)"
fi

# --- ntfy-dispatcher rules (only if the dispatcher is configured here) ---------------------
if [ -f "$DISPATCH_CFG" ] && command -v ntfy-dispatcher >/dev/null; then
  if ! grep -q 'id = "logscan_alert"' "$DISPATCH_CFG"; then
    backup "$DISPATCH_CFG"
    cat "$HERE/dispatcher-rules.toml" >> "$DISPATCH_CFG"
    if ! ntfy-dispatcher config check >/dev/null; then
      echo "dispatcher config check failed — restoring $DISPATCH_CFG" >&2
      cp -a "$DISPATCH_CFG.orig-$STAMP" "$DISPATCH_CFG"; exit 1
    fi
    echo "  added dispatcher rules logscan_alert / logscan_digest / logscan_error"
  fi
fi

# --- units + host drop-in --------------------------------------------------------------------
for u in logscan.service logscan.timer; do
  backup "$UNITS/$u"
  install -o root -g root -m 0644 "$HERE/systemd/$u" "$UNITS/$u"
done
HANDLER=""
for h in ntfy-job-failed@.service ntfy-unit-failed@.service; do
  [ -e "$UNITS/$h" ] || [ -e "/usr/lib/systemd/system/$h" ] || [ -e "/lib/systemd/system/$h" ] && { HANDLER="${h%@.service}@%N.service"; break; }
done
install -d -m 0755 "$UNITS/logscan.service.d"
{
  echo "# Written by logscan install.sh for $(hostname) on $STAMP."
  echo "[Unit]"
  [ -n "$HANDLER" ] && echo "OnFailure=$HANDLER"
  echo "[Service]"
  # Primary group is adm (unit); the rest as supplementary groups, plus logscan for the API key.
  echo "SupplementaryGroups=$(printf '%s ' "${GROUPS_PRESENT[@]}" | sed 's/\badm \?//')logscan"
} > "$UNITS/logscan.service.d/10-host.conf"
echo "  drop-in: $(tr '\n' ' ' < "$UNITS/logscan.service.d/10-host.conf")"
systemctl daemon-reload
systemd-analyze verify --man=no logscan.service logscan.timer 2>&1 | grep -v '^$' || true

# --- verify as the service user (nothing stored or pushed) ---------------------------------
echo "--- rules check ---"
runuser -u logscan -- /usr/local/bin/logscan --config "$ETC/config.toml" rules check | tail -2
runuser -u logscan -- /usr/local/bin/logscan --config "$ETC/config.toml" skills check | head -1
echo "--- dry run, last 24h ---"
DRY="$(mktemp -d)"; chown logscan "$DRY"
runuser -u logscan -- /usr/local/bin/logscan --config "$ETC/config.toml" --state-dir "$DRY" \
  run --dry-run --no-llm --since 24h || true
rm -rf "$DRY"

# --- first run + timer -------------------------------------------------------------------------
if [ "$FIRST_RUN" -eq 1 ]; then
  echo "--- first run: systemctl start logscan.service ---"
  systemctl start logscan.service || echo "  logscan.service exited non-zero, see journal below"
  journalctl -u logscan.service -n 6 --no-pager -o cat
fi
systemctl enable --now logscan.timer
systemctl list-timers logscan.timer --no-pager | head -2

cat <<'EOT'

Next:
  - review /etc/logscan/config.toml ([lists], [llm] host_context), then: logscan --config /etc/logscan/config.toml rules check
  - optional LLM skills: put the key into /etc/logscan/llm-api-key without echoing it:
      sudo bash -c 'read -rsp "API key: " k; echo; umask 027; printf "%s\n" "$k" > /etc/logscan/llm-api-key; chgrp logscan /etc/logscan/llm-api-key'
      sudo -u logscan logscan --config /etc/logscan/config.toml llm-check
    and set llm.enabled = true
  - reports: /var/lib/logscan/reports/latest.md (readable by group adm)
EOT
