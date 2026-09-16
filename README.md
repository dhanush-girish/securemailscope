# SecureMailScope

AI-assisted cryptographic security posture assessment for secure email communications (SIH #26159). The project has two connected parts: a **Phase 1 capture & parsing pipeline** that turns live mail server traffic into structured, labeled session data, and a **Phase 2 AI/ML pipeline** that scores that data for risk and serves it to a live dashboard.

---
## 🚀 Key Features

- **Automated Preprocessing**: Maps raw network data (ports, negotiated TLS versions, ciphers) to a normalized schema, gracefully handling missing fields.
- **Feature Engineering**: Extracts security indicators like weak ciphers, deprecated TLS versions, weak certificate signatures, and key exchange vulnerabilities.
- **Machine Learning Models**:
  - **Random Forest Classifier**: Determines the risk level (Low, Medium, High, Critical) based on extracted features.
  - **Isolation Forest**: Performs unsupervised anomaly detection to flag sessions that look unusual.
- **FastAPI Backend**: Serves a high-performance REST API (`/analyze`, `/history`) for live scoring and dashboard integration.
- **Live Dashboard**: A real-time monitoring interface that polls the API to display session summaries, security scores, and specific vulnerability recommendations.
- **Seamless Integration**: Includes a file watcher (`watch_and_forward.py`) that instantly forwards new sessions from the packet capture tool directly to the pipeline.

---

## 📁 Project Structure

```text
securemailscope/
├── Phase 1/
│   ├── phase2_tls_decoder.py        # Decodes TLS handshake fields (version, cipher, cert) from a .pcap
│   ├── db_stream.py                 # [confirm] streams/watches the local capture DB for new rows
│   ├── db_to_json.py                # Exports rows from the local capture DB into JSON
│   ├── firmware_grabber.py          # [confirm purpose — not part of the original capture pipeline spec]
│   ├── start.sh                     # Starts continuous capture + parsing in the background
│   └── stop.sh                      # Stops the running capture pipeline gracefully
├── api/
│   └── main.py                      # FastAPI server (/analyze, /history)
├── dashboard/
│   └── index.html                   # Real-time monitoring dashboard
├── data/
│   ├── generate_synthetic_data.py   # Synthetic data generator for training
│   └── load_real_csv.py             # Converts real CSV exports to pipeline JSON
├── db/                              # [confirm] local SQLite database(s) live here
├── integration/
│   ├── watch_and_forward.py         # File watcher for live data ingestion
│   └── send_session.py              # Direct integration script
├── pipeline/
│   ├── preprocessing.py             # Data normalization & feature engineering
│   ├── train_models.py              # Model training script
│   └── saved_models/                # Serialized models and preprocessors
└── sample_data/
    └── sample_input.json            # Example record for manual testing
```

> **Note:** `db_stream.py`, `db_to_json.py`, and `firmware_grabber.py` are documented above based on their filenames — whoever owns these should confirm/correct these one-line descriptions so the README stays accurate.

---

## ⚙️ How it Works (end to end)

1. **Capture** — `Phase 1/start.sh` launches a continuous packet capture on the mail server's interface, rotating to a new `.pcap` file at a fixed interval.
2. **Parse** — as each capture file completes, `phase2_tls_decoder.py` extracts the TLS handshake fields (negotiated version, cipher suite, certificate details) and writes structured rows into the local capture database.
3. **Export/forward** — `db_to_json.py` / `db_stream.py` move that structured data out of the local database, either as a JSON export or a live stream, toward the Phase 2 pipeline.
4. **Ingestion** — `integration/watch_and_forward.py` (or `send_session.py`) picks up new sessions and forwards them to the FastAPI backend's `/analyze` endpoint.
5. **Preprocessing** — `pipeline/preprocessing.py` normalizes the data and engineers features (weak ciphers, deprecated protocols, weak certificate signatures).
6. **Inference** — the Random Forest and Isolation Forest models compute a risk score and flag anomalies.
7. **Monitoring** — the dashboard polls the API and displays live session summaries, scores, and recommendations.

---

## 🔧 Configuration — fill these in before running

These are the paths, keys, and settings that are **specific to your machine and setup** and must be filled in — none of these should be committed to git with real values.

### Phase 1 — capture pipeline (`Phase 1/`)

| Setting | Where it's set | What to put here |
|---|---|---|
| Network interface | passed as an argument to `start.sh` (e.g. `./start.sh <label> eth0 60`) | Run `ip a` on the machine doing the capture and use the interface actually carrying mail traffic (confirm with `ip a` — don't assume `eth0`) |
| Capture rotation interval | third argument to `start.sh` | Seconds between pcap file rotations (60 is a reasonable default) |
| Capture label | first argument to `start.sh` | e.g. `vulnerable` or `hardened` — tags every session in this run |
| Local database path | inside the capture pipeline config/orchestrator | Confirm the actual path used (e.g. `Phase 1/securemailscope.db` or under `db/`) and make sure it's in `.gitignore` |
| BPF capture filter | inside the capture pipeline config | Typically `tcp port 25` for SMTP; adjust if capturing IMAP/POP3 too |

### Data forwarding (`db_to_json.py` / `db_stream.py` / `integration/`)

| Setting | What to put here |
|---|---|
| Target API URL | The FastAPI backend's `/analyze` (or `/ingest`) endpoint — e.g. `http://<api-host>:8000/analyze` |
| API key | The shared secret used to authenticate requests to that endpoint — **never commit the real key**; store it as an environment variable or in a local `.env` file that's gitignored |
| Since-ID / checkpoint file | If forwarding incrementally rather than resending everything, confirm where the "last sent row" checkpoint is tracked |

### API backend (`api/main.py`)

| Setting | What to put here |
|---|---|
| Port | Default `8000` — change if that port is already in use |
| Model paths | Confirm `pipeline/saved_models/` contains the trained models before starting the API, or it will fail to load them |
| API key (server side) | Must match whatever key the Phase 1 forwarding scripts send |

**Suggested practice:** put all of the above into a single `.env` file at the project root (e.g. `API_KEY=`, `TARGET_URL=`, `CAPTURE_INTERFACE=`, `DB_PATH=`) and load it in each script with `python-dotenv`, rather than hardcoding values — this makes it a one-file change to move between machines and keeps secrets out of git.

Add to `.gitignore` if not already present:
```
*.pcap
*.db
*.log
*.pid
.env
__pycache__/
captures/
saved_models/*.pkl
```

---

## 💻 Running Locally

### 1. Setup Environment
```bash
pip install -r requirements.txt
```

### 2. Start the Phase 1 capture pipeline
```bash
cd "Phase 1"
chmod +x start.sh stop.sh
sudo ./start.sh <label> <interface> <rotate_seconds>
# e.g. sudo ./start.sh vulnerable eth0 60
```
Stop it with:
```bash
sudo ./stop.sh
```

### 3. Generate Data & Train Models
```bash
python data/generate_synthetic_data.py
python pipeline/train_models.py
```

### 4. Start the API Server
```bash
python api/main.py
```
API available at `http://localhost:8000`, docs at `http://localhost:8000/docs`.

### 5. View the Dashboard
```text
http://localhost:8000/dashboard/
```

### 6. Live Data Integration
```bash
python integration/watch_and_forward.py path/to/sessions_export.csv
```
or, to forward directly from the Phase 1 database:
```bash
python "Phase 1"/db_to_json.py   # then feed the export into integration/send_session.py
```

---

## 🛠 Manual Testing
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  --data-binary @sample_data/sample_input.json
```
