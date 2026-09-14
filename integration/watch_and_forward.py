"""
watch_and_forward.py

The missing link: Ubuntu detection tool -> automatic JSON -> FastAPI.

WHAT THIS SOLVES
----------------
Right now you paste JSON into Swagger by hand. This script removes that
step entirely, without needing to touch your teammates' Ubuntu-side code
at all. It watches whatever CSV file their tool writes/appends session
rows to (like sessions_export.csv), and the moment new rows appear, it
automatically converts and POSTs each one to FastAPI's /analyze endpoint.
Results then show up on the dashboard on their own.

    Ubuntu tool writes rows --> this script notices --> POST /analyze
    --> FastAPI predicts + scores --> dashboard polls /history --> done

WHY A FILE WATCHER (vs. asking teammates to add code)
------------------------------------------------------
You don't know your teammates' tool's language/internals, and they're not
available right now. A file watcher works regardless of what their tool is
written in, as long as it writes session data to a file on disk that grows
over time (which is exactly what sessions_export.csv already does -- new
pcaps' worth of rows get appended as captures happen).

If your teammates ARE available later and their tool is Python, the more
"real-time" alternative is integration/send_session.py -- a single function
they can call directly after building each record, no file/polling needed.
Both approaches are valid; use whichever fits how their tool actually runs.

USAGE
-----
    # Terminal 1: your API (already running)
    python api/main.py

    # Terminal 2: this watcher, pointed at wherever the Ubuntu tool writes
    python integration/watch_and_forward.py sample_data/sessions_export.csv

    # Optional: point at a different API host/port, or a network share
    python integration/watch_and_forward.py path\\to\\export.csv http://192.168.1.50:8000/analyze

    # Optional: also replay every row already in the file on startup
    # (off by default, so re-running this script doesn't re-send old data)
    python integration/watch_and_forward.py sample_data/sessions_export.csv --replay
"""

import os
import sys
import time
import json

import requests
import pandas as pd
import numpy as np

DEFAULT_API_URL = "http://localhost:8000/analyze"
POLL_INTERVAL_SEC = 2


def _clean_value(v):
    if isinstance(v, (np.generic,)):
        v = v.item()
    if isinstance(v, float) and np.isnan(v):
        return None
    return v


def _row_to_record(row: pd.Series) -> dict:
    return {k: _clean_value(v) for k, v in row.items()}


def send_record(record: dict, api_url: str) -> dict | None:
    try:
        resp = requests.post(api_url, json=record, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f"  [!] Failed to reach API at {api_url}: {e}")
        return None


def watch(csv_path: str, api_url: str, replay_existing: bool = False):
    last_seen_id = None
    seen_row_count = 0
    use_id_column = None  # decided on first successful read

    print(f"Watching {csv_path}")
    print(f"Forwarding new sessions to {api_url}")
    print(f"Poll interval: {POLL_INTERVAL_SEC}s. Press Ctrl+C to stop.\n")

    # Establish baseline so we only send NEW rows from here on, unless
    # --replay was passed.
    if os.path.exists(csv_path) and not replay_existing:
        try:
            df = pd.read_csv(csv_path)
            use_id_column = "id" in df.columns
            if use_id_column and len(df):
                last_seen_id = df["id"].max()
            seen_row_count = len(df)
            print(f"Baseline established: {seen_row_count} existing row(s) will NOT be resent.")
            print("(pass --replay to also process everything already in the file)\n")
        except Exception as e:
            print(f"Could not establish baseline ({e}); will process from scratch.\n")

    while True:
        try:
            if not os.path.exists(csv_path):
                time.sleep(POLL_INTERVAL_SEC)
                continue

            df = pd.read_csv(csv_path)
            if use_id_column is None:
                use_id_column = "id" in df.columns

            if use_id_column:
                new_rows = df if last_seen_id is None else df[df["id"] > last_seen_id]
            else:
                new_rows = df.iloc[seen_row_count:]

            if len(new_rows):
                print(f"[{time.strftime('%H:%M:%S')}] {len(new_rows)} new session(s) detected")
                for _, row in new_rows.iterrows():
                    record = _row_to_record(row)
                    result = send_record(record, api_url)
                    if result and result.get("results"):
                        r = result["results"][0]
                        print(
                            f"  -> {r.get('protocol','?')} {r.get('tls_version','?')} "
                            f"=> {r['risk_level'].upper()} (score {r['security_score']}) "
                            f"{'[ANOMALY]' if r.get('is_anomaly') else ''}"
                        )
                if use_id_column and len(df):
                    last_seen_id = df["id"].max()
                seen_row_count = len(df)

            time.sleep(POLL_INTERVAL_SEC)

        except KeyboardInterrupt:
            print("\nStopped watching.")
            break
        except Exception as e:
            print(f"[!] Watcher error (will retry): {e}")
            time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python integration/watch_and_forward.py <csv_path> [api_url] [--replay]")
        sys.exit(1)

    args = sys.argv[1:]
    replay = "--replay" in args
    args = [a for a in args if a != "--replay"]

    csv_path = args[0]
    api_url = args[1] if len(args) > 1 else DEFAULT_API_URL

    watch(csv_path, api_url, replay_existing=replay)
