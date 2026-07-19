#!/usr/bin/env bash
set -euo pipefail

echo "Running NetSpecter post-update maintenance..."

install_safe_suricata_logrotate() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Skipping Suricata logrotate maintenance; root privileges are required." >&2
    return 0
  fi

  mkdir -p /var/log/suricata
  cat >/etc/logrotate.d/suricata <<'EOF'
/var/log/suricata/*.log
/var/log/suricata/*.json
{
        rotate 14
        missingok
        compress
        copytruncate
        sharedscripts
        postrotate
                if [ -s /var/run/suricata.pid ]; then
                        /bin/kill -HUP "$(cat /var/run/suricata.pid)" 2>/dev/null || true
                fi
        endscript
}
EOF
}

refresh_suricata_rules() {
  if ! command -v suricata >/dev/null 2>&1; then
    echo "Suricata is not installed; skipping IDS rule maintenance."
    return 0
  fi

  mkdir -p /var/lib/suricata/rules /var/log/suricata

  local rules_file="/var/lib/suricata/rules/suricata.rules"
  local refresh_rules=0
  if [ ! -s "$rules_file" ]; then
    refresh_rules=1
  elif [ "$(find "$rules_file" -mtime +14 -print -quit 2>/dev/null)" ]; then
    refresh_rules=1
  fi

  if [ "$refresh_rules" -eq 1 ] && command -v suricata-update >/dev/null 2>&1; then
    if ! suricata-update; then
      echo "WARNING: suricata-update failed; leaving existing IDS rules in place." >&2
    fi
  elif [ "$refresh_rules" -eq 1 ]; then
    echo "suricata-update is not installed; skipping IDS rule refresh."
  else
    echo "Suricata rules are present and less than 14 days old; skipping rule refresh."
  fi

  if [ "$refresh_rules" -eq 0 ]; then
    echo "Suricata rules are fresh; skipping validation restart."
    if ! systemctl is-active --quiet suricata; then
      timeout 20s systemctl enable --now suricata >/dev/null 2>&1 || true
    fi
  elif suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
    systemctl reset-failed suricata >/dev/null 2>&1 || true
    systemctl restart suricata >/dev/null 2>&1 || true
  else
    echo "WARNING: Suricata configuration validation failed; not restarting Suricata." >&2
  fi
}

install_safe_suricata_logrotate
refresh_suricata_rules
systemctl reset-failed logrotate >/dev/null 2>&1 || true

echo "NetSpecter post-update maintenance complete."
