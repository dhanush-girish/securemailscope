#!/bin/bash
# Starts continuous capture + parsing in the background.
# Run with sudo, since tcpdump needs raw socket access:
#   sudo ./start.sh vulnerable eth0
#
# Args: [label] [interface] [rotate_seconds]  (all optional, sensible defaults used)

LABEL="${1:-live_capture}"
INTERFACE="${2:-eth0}"
ROTATE="${3:-60}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f monitor.pid ] && kill -0 "$(cat monitor.pid)" 2>/dev/null; then
    echo "Already running (PID $(cat monitor.pid)). Run ./stop.sh first if you want to restart."
    exit 1
fi

nohup python3 -u orchestrator.py --label "$LABEL" --interface "$INTERFACE" --rotate-seconds "$ROTATE" > monitor.log 2>&1 &
echo $! > monitor.pid

echo "Started. PID: $(cat monitor.pid)"
echo "Label: $LABEL | Interface: $INTERFACE | Rotating every ${ROTATE}s"
echo "Logs: $SCRIPT_DIR/monitor.log"
echo "Database: $SCRIPT_DIR/securemailscope.db"
echo "Stop with: ./stop.sh"
