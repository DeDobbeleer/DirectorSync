#!/usr/bin/env bash
# ESA / Rsyslog phase-by-phase debugger (NO jq, uses /var/log/messages)
# Usage:
#   sudo ./esa_rsyslog_phases.sh backend1 backend2
#   sudo BACKENDS="backend1 backend2" ./esa_rsyslog_phases.sh
set -euo pipefail

# -------- Defaults (override with env) --------
PORT_TLS="${PORT_TLS:-6514}"
PORT_TCP="${PORT_TCP:-514}"
PORT_UDP="${PORT_UDP:-514}"
ACTION_NAME="${ACTION_NAME:-lp_tls_rr}"
IMPSTATS_FILE="${IMPSTATS_FILE:-/var/log/rsyslog_stats.json}"
WORKDIR="${WORKDIR:-/var/spool/rsyslog}"
FALLBACK_FILE="${FALLBACK_FILE:-/var/log/esa_fallback-buffer.log}"
LOG_MESSAGES="${LOG_MESSAGES:-/var/log/messages}"

# -------- Backends (args or env) --------
if [[ $# -ge 1 ]]; then
  BACKENDS=("$@")
elif [[ -n "${BACKENDS-}" ]]; then
  # shellcheck disable=SC2206
  BACKENDS=(${BACKENDS})
else
  echo "Enter space-separated backends (e.g., collector1 collector2):"
  read -r line
  # shellcheck disable=SC2206
  BACKENDS=(${line})
fi
[[ ${#BACKENDS[@]} -ge 1 ]] || { echo "[ERR] No backends provided."; exit 1; }

# -------- Helpers --------
sec()  { echo -e "\n== $* =="; }
ok()   { echo "[OK]  $*"; }
warn() { echo "[WARN] $*"; }
err()  { echo "[ERR] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

tcp_test() {
  local host=$1 port=$2
  timeout 3 bash -c "cat </dev/null >/dev/tcp/${host}/${port}" >/dev/null 2>&1
}

press_enter() { echo; read -r -p "Press ENTER to return to menu... " _; }

# -------- Phase Functions --------
phase1_active() {
  sec "1) Is rsyslog active?"
  if have rsyslogd; then
    if rsyslogd -N1 >/tmp/rs_check 2>&1; then ok "Config syntax OK (rsyslogd -N1)"; else err "Config check failed:"; cat /tmp/rs_check; fi
    rsyslogd -v | head -n1 || true
  else
    err "rsyslogd not found in PATH"
  fi

  if have systemctl; then
    if systemctl is-active --quiet rsyslog; then ok "Service active"; else warn "Service NOT active"; systemctl status rsyslog --no-pager || true; fi
  else
    warn "systemctl not available"
  fi
  press_enter
}

phase2_listening() {
  sec "2) Is rsyslog listening? (UDP ${PORT_UDP}, TCP ${PORT_TCP}, TLS ${PORT_TLS})"
  if have ss; then
    ss -lntu | egrep ":${PORT_UDP}|:${PORT_TCP}|:${PORT_TLS}" || warn "Expected listeners not found. Check inputs/TLS listener config."
  else
    warn "'ss' not found — cannot list sockets."
  fi
  echo
  if have firewall-cmd; then
    echo "firewalld open ports:"
    firewall-cmd --list-ports || true
  fi
  press_enter
}

phase3_reachable() {
  sec "3) Target reachable? (TLS ${PORT_TLS})"
  for H in "${BACKENDS[@]}"; do
    if tcp_test "$H" "$PORT_TLS"; then ok "$H:${PORT_TLS} reachable"; else err "$H:${PORT_TLS} UNREACHABLE"; fi
  done
  echo
  if have ss; then
    echo "Outgoing connections (rsyslog -> :${PORT_TLS}):"
    ss -ntp "dst :${PORT_TLS}" | grep rsyslog || warn "No active rsyslog connections on :${PORT_TLS} (may be idle or failing)."
  fi
  press_enter
}

phase4_target_live() {
  sec "4) Target status in live (tail /var/log/messages for omfwd connection/suspend/resume)"
  [[ -f "$LOG_MESSAGES" ]] || { err "$LOG_MESSAGES not found"; press_enter; return; }
  echo "Live view — Ctrl+C to stop"
  echo "Filtering: omfwd connection|suspend|resume"
  # Use stdbuf to avoid block buffering
  stdbuf -oL tail -n0 -F "$LOG_MESSAGES" | grep -iE 'omfwd.*(connection|suspend|resume)'
}

phase5_buffer_live() {
  sec "5) Buffering status in live (impstats for ${ACTION_NAME} + fallback file)"
  [[ -f "$IMPSTATS_FILE" ]] || warn "$IMPSTATS_FILE not found (impstats may be disabled)."
  echo "Live view — Ctrl+C to stop"
  echo "Stream A: impstats lines for actionName=${ACTION_NAME}"
  echo "Stream B: fallback file (only during suspension): $FALLBACK_FILE"
  echo

  # Run two tails in parallel, prefixing source
  pids=()
  if [[ -f "$IMPSTATS_FILE" ]]; then
    ( stdbuf -oL tail -n0 -F "$IMPSTATS_FILE" \
      | sed 's/^@cee: //' \
      | grep -F "\"actionName\":\"${ACTION_NAME}\"" \
      | sed -u "s/^/[impstats] /" ) &
    pids+=($!)
  fi

  if [[ -f "$FALLBACK_FILE" ]]; then
    ( stdbuf -oL tail -n0 -F "$FALLBACK_FILE" \
      | sed -u "s/^/[fallback] /" ) &
    pids+=($!)
  else
    warn "Fallback file not present (OK if never suspended yet)."
  fi

  # Always include /var/log/messages suspension/resume in this view
  if [[ -f "$LOG_MESSAGES" ]]; then
    ( stdbuf -oL tail -n0 -F "$LOG_MESSAGES" \
      | grep -iE 'omfwd.*(suspend|resume)' \
      | sed -u "s/^/[messages] /" ) &
    pids+=($!)
  fi

  trap 'kill ${pids[@]} 2>/dev/null || true' INT TERM
  wait "${pids[@]}" 2>/dev/null || true
  trap - INT TERM
}

menu() {
  clear
  cat <<EOF
==========================
 ESA Rsyslog Phase Checks
 Backends: ${BACKENDS[*]}
==========================
1) Rsyslog active ?
2) Rsyslog listening ?
3) Target reachable ?
4) Target status (live tail)
5) Buffering status (live tail)
q) Quit
EOF
  echo -n "Select: "
}

# -------- Main loop --------
while true; do
  menu
  read -r choice
  case "$choice" in
    1) phase1_active ;;
    2) phase2_listening ;;
    3) phase3_reachable ;;
    4) phase4_target_live ;;
    5) phase5_buffer_live ;;
    q|Q) echo "Bye."; exit 0 ;;
    *) echo "Unknown choice"; sleep 1 ;;
  esac
done
