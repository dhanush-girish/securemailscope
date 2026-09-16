#!/bin/bash
# Stops the running capture+parse orchestrator gracefully.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f monitor.pid ]; then
    echo "No running monitor found (monitor.pid missing)."
    exit 1
fi

PID=$(cat monitor.pid)
if ! kill -0 "$PID" 2>/dev/null; then
    echo "Process $PID is not running. Cleaning up stale pid file."
    rm -f monitor.pid
    exit 1
fi

echo "Stopping monitor (PID $PID)... this will also process the last in-progress capture file."
kill -TERM "$PID"

# wait for it to actually exit, up to 15s
for i in $(seq 1 15); do
    if ! kill -0 "$PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

rm -f monitor.pid
echo "Stopped. Check monitor.log for the final processing output."
