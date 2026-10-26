#!/bin/bash
# Resumable launcher for the capture grid (run as root in WSL/Linux; safe to re-run, finished cells are skipped).
LOCK=/tmp/p1920b.lock
if [ -f "$LOCK" ] && kill -0 "$(cat "$LOCK" 2>/dev/null)" 2>/dev/null; then exit 0; fi
echo $$ > "$LOCK"
SRC="$(cd "$(dirname "$0")" && pwd)"
LOG="$SRC/../logs/b_twin.log"; mkdir -p "$SRC/../logs"
B=${LAB:-/opt/p1920b}
for f in b_twin.py b_osslclient.py; do sed 's/\r$//' "$SRC/$f" > "$B/$f"; done
grep -q "ALL DONE" "$LOG" 2>/dev/null && { rm -f "$LOCK"; exit 0; }
service openvswitch-switch start >/dev/null 2>&1
cd $B
LAB=$B CAP=$B/caps REPS=10 DUR=20 python3 b_twin.py all 2>&1 | grep --line-buffered -v sch_htb >> "$LOG"
rm -f "$LOCK"
