#!/usr/bin/env bash
# bridge_ctl.sh — start/stop/status of the LIVE0 console bridge on the LAN worker.
#
#   bridge_ctl.sh start  <payload_port> <host_port> <lifetime_s>
#   bridge_ctl.sh stop
#   bridge_ctl.sh status
#
# Deliberately a script rather than an inline SSH command line: the quoting of a compound
# backgrounding command does not survive `ssh host "..."` reliably, and a silent failure here
# looks exactly like "the payload never attached".
set -u

SELF="console_bridge.py"
PATTERN="[c]onsole_bridge.py"
LOG=/tmp/console_bridge.log
SCRIPT=/tmp/console_bridge.py

action="${1:-status}"

case "$action" in
  start)
    payload_port="${2:-9025}"
    host_port="${3:-9026}"
    lifetime="${4:-900}"
    pkill -f "$PATTERN" >/dev/null 2>&1
    sleep 0.5
    rm -f "$LOG"
    if [ ! -f "$SCRIPT" ]; then
      echo "BRIDGE-START-FAILED missing $SCRIPT"
      exit 2
    fi
    setsid nohup python3 "$SCRIPT" "$payload_port" "$host_port" "$lifetime" "$LOG" \
      >/dev/null 2>&1 < /dev/null &
    sleep 2
    if ss -ltn 2>/dev/null | grep -q ":$host_port"; then
      echo "BRIDGE-STARTED payload_port=$payload_port host_port=$host_port lifetime=$lifetime"
      ss -ltn 2>/dev/null | grep -E ":($payload_port|$host_port)" | tr -s ' '
    else
      echo "BRIDGE-START-FAILED host_port=$host_port not listening"
      [ -f "$LOG" ] && tail -5 "$LOG"
      exit 3
    fi
    ;;
  stop)
    pkill -f "$PATTERN" >/dev/null 2>&1
    echo "BRIDGE-STOPPED"
    ;;
  status)
    ss -ltn 2>/dev/null | grep -E ":(9025|9026)" | tr -s ' ' || true
    ps -o pid=,etime=,args= -C python3 2>/dev/null | grep "$PATTERN" || echo "(no bridge process)"
    [ -f "$LOG" ] && tail -5 "$LOG" || echo "(no bridge log)"
    ;;
  *)
    echo "usage: $0 {start|stop|status}" >&2
    exit 64
    ;;
esac
