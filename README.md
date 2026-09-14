# SecureMailScope — AI/ML Pipeline

An AI/ML-powered network analysis component built for the SecureMailScope problem statement (SIH #26159). This pipeline processes live network packet capture data (parsed into CSV/JSON format), performs feature engineering, and uses machine learning to classify risk and detect anomalies. Results are served in real-time to a live monitoring dashboard.

## 🚀 Key Features

- **Automated Preprocessing**: Maps raw network data (ports, negotiated TLS versions, ciphers) to a normalized schema, gracefully handling missing fields.
- **Feature Engineering**: Extracts security indicators like weak ciphers, deprecated TLS versions, weak certificate signatures, and key exchange vulnerabilities.
- **Machine Learning Models**:
  - **Random Forest Classifier**: Determines the risk level (Low, Medium, High, Critical) based on extracted features.
  - **Isolation Forest**: Performs unsupervised anomaly detection to flag sessions that look unusual.
- **FastAPI Backend**: Serves a high-performance REST API (`/analyze`, `/history`) for live scoring and dashboard integration.
- **Live Dashboard**: A real-time monitoring interface that polls the API to display session summaries, security scores, and specific vulnerability recommendations.
- **Seamless Integration**: Includes a file watcher (`watch_and_forward.py`) that instantly forwards new sessions from the packet capture tool directly to the pipeline.

## 📁 Project Structure

```text
securemailscope/
├── api/
│   └── main.py                      # FastAPI server (/analyze, /history)
├── dashboard/
│   └── index.html                   # Real-time monitoring dashboard
├── data/
│   ├── generate_synthetic_data.py   # Synthetic data generator for training
│   └── load_real_csv.py             # Converts real CSV exports to pipeline JSON
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

## ⚙️ How it Works

1. **Ingestion**: Network sessions are captured and written to a CSV file. The `watch_and_forward.py` script detects new rows and forwards them to the API.
2. **Preprocessing**: The data is normalized. Weak certificates, deprecated protocols, and weak ciphers are identified.
3. **Inference**: The preprocessed features are passed through the Random Forest and Isolation Forest models to compute a risk score and detect anomalies.
4. **Monitoring**: The FastAPI backend stores the results, which are continuously polled and displayed by the live dashboard.

## 💻 Running Locally

### 1. Setup Environment
Ensure you have Python 3.8+ installed. Install the required dependencies:
```bash
pip install -r requirements.txt
```

### 2. Generate Data & Train Models
You can train the models using synthetic data combined with any real dataset provided.
```bash
# Generate synthetic training data
python data/generate_synthetic_data.py

# Train the Random Forest & Isolation Forest models
python pipeline/train_models.py
```

### 3. Start the API Server
Launch the FastAPI backend:
```bash
python api/main.py
```
*The API will be available at `http://localhost:8000` with Swagger documentation at `http://localhost:8000/docs`.*

### 4. View the Dashboard
Open your browser and navigate to the dashboard served by the API:
```text
http://localhost:8000/dashboard/
```

### 5. Live Data Integration
To automatically analyze new sessions as they are captured, run the file watcher in a separate terminal:
```bash
python integration/watch_and_forward.py path/to/sessions_export.csv
```

## 🛠 Manual Testing
You can manually test the pipeline by sending a sample JSON payload:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  --data-binary @sample_data/sample_input.json
```
