"""
FastAPI backend for SecureMailScope.

POST /analyze         -> analyze one session record (or {"sessions":[...]} for a batch)
GET  /history          -> recent analysis results (used by the live dashboard)
GET  /stats            -> aggregate stats (total, risk counts, avg score, anomalies)
GET  /health           -> model/pipeline load status
GET  /metadata         -> model metadata (feature list, label classes, training info)

Run with:
    uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
"""

import os
import sys
import json
import uuid
import logging
from datetime import datetime
from collections import deque
from typing import Optional, List, Union

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline.preprocessing import (
    SecureMailPreprocessor, normalize_record, engineer_features,
    describe_weaknesses, recommend_actions, records_to_feature_df,
    compute_security_score,
)
import joblib

# ---------------------------------------------------------------------------
# Supabase integration (graceful — falls back to in-memory if unavailable)
# ---------------------------------------------------------------------------
_supabase_available = False
try:
    from db.supabase_client import insert_results as sb_insert_results
    from db.supabase_client import get_history as sb_get_history
    from db.supabase_client import get_stats as sb_get_stats
    _supabase_available = True
except Exception as e:
    logging.warning("Supabase module not available, using in-memory only: %s", e)

logger = logging.getLogger("securemailscope.api")

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pipeline", "saved_models")

app = FastAPI(title="SecureMailScope API", version="1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the dashboard from this same server/port so there's no separate
# static file server to run. Visit http://localhost:8000/dashboard/
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
if os.path.isdir(DASHBOARD_DIR):
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

# ---------------------------------------------------------------------------
# Load pipeline + models once at startup
# ---------------------------------------------------------------------------
_state = {"loaded": False}


def load_models():
    preprocessor = SecureMailPreprocessor.load(os.path.join(MODEL_DIR, "preprocessor.pkl"))
    rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
    iso_model = joblib.load(os.path.join(MODEL_DIR, "iso_model.pkl"))
    label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
    with open(os.path.join(MODEL_DIR, "metadata.json")) as f:
        metadata = json.load(f)
    _state.update({
        "preprocessor": preprocessor,
        "rf_model": rf_model,
        "iso_model": iso_model,
        "label_encoder": label_encoder,
        "metadata": metadata,
        "loaded": True,
    })


import asyncio

@app.on_event("startup")
async def startup_event():
    load_models()
    asyncio.create_task(background_ml_worker())


async def background_ml_worker():
    """Polls Supabase for raw rows inserted by the cyber team, runs them through the ML pipeline, and updates them."""
    while True:
        if _supabase_available and _state["loaded"]:
            try:
                from db.supabase_client import get_unprocessed_rows, update_row_ml_fields
                rows = get_unprocessed_rows(limit=50)
                for row in rows:
                    try:
                        # Process the raw row
                        ml_result = _analyze_one(row)
                        # The analyzed result has ml fields but we only want to update the DB
                        update_row_ml_fields(row["id"], ml_result)
                        logger.info(f"Processed ML fields for raw row {row['id']}")
                    except Exception as e:
                        logger.error(f"Failed to process row {row.get('id')}: {e}")
            except Exception as e:
                logger.error(f"Background worker error: {e}")
        
        await asyncio.sleep(2)  # poll every 2 seconds


# In-memory ring buffer — serves as a fallback cache when Supabase is
# unreachable and as a fast local cache for the most recent results.
HISTORY = deque(maxlen=200)


class SessionRecord(BaseModel):
    """
    Loosely typed on purpose: we accept arbitrary extra fields (Ubuntu tool's
    real JSON may include things we don't use yet) and rely on
    pipeline/preprocessing.py's FIELD_ALIASES + normalize_record to pull out
    what we need. Nothing here is required -- missing fields are handled.
    """
    model_config = ConfigDict(extra="allow")


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    sessions: Optional[List[dict]] = None


def _analyze_one(raw_record: dict) -> dict:
    if not _state["loaded"]:
        raise HTTPException(status_code=503, detail="Models not loaded yet")

    norm = normalize_record(raw_record)
    df = records_to_feature_df([raw_record])

    X = _state["preprocessor"].column_transformer.transform(df)
    if hasattr(X, "toarray"):
        X = X.toarray()

    rf = _state["rf_model"]
    le = _state["label_encoder"]
    iso = _state["iso_model"]

    probs = rf.predict_proba(X)[0]
    pred_idx = int(np.argmax(probs))
    risk_label = le.classes_[pred_idx]
    confidence = float(probs[pred_idx])

    anomaly_raw = iso.predict(X)[0]  # -1 = anomaly, 1 = normal
    is_anomaly = bool(anomaly_raw == -1)
    anomaly_score = float(iso.decision_function(X)[0])  # higher = more normal

    weaknesses = describe_weaknesses(norm)
    recommendations = recommend_actions(norm)
    # Deterministic, points-deduction score -- NOT derived from classifier
    # confidence. Every distinct weakness (weak TLS version, weak key
    # exchange, weak authentication, weak encryption, cert issues, etc.)
    # costs fixed points, so the score always drops further as MORE flags
    # are raised, and rises back up as fewer are. See compute_security_score()
    # in pipeline/preprocessing.py for the exact point values.
    security_score = compute_security_score(norm)
    if is_anomaly:
        security_score = max(0, security_score - 15)

    result = {
        "result_id": str(uuid.uuid4()),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "session_id": norm.get("session_id"),
        "protocol": norm.get("protocol"),
        "tls_version": norm.get("tls_version"),
        "cipher_suite": norm.get("cipher_suite"),
        "risk_level": risk_label,
        "risk_confidence": round(confidence, 3),
        "class_probabilities": {cls: round(float(p), 3) for cls, p in zip(le.classes_, probs)},
        "is_anomaly": is_anomaly,
        "anomaly_score": round(anomaly_score, 4),
        "security_score": security_score,
        "detected_weaknesses": weaknesses,
        "recommendations": recommendations,
    }
    return result


def _persist_results(results: list[dict]):
    """Save results to Supabase (primary) and in-memory cache (fallback)."""
    # Always update the local cache
    for r in results:
        HISTORY.appendleft(r)

    # Persist to Supabase
    if _supabase_available:
        try:
            sb_insert_results(results)
            logger.info("Persisted %d result(s) to Supabase", len(results))
        except Exception as e:
            logger.error("Failed to persist to Supabase (results kept in memory): %s", e)


@app.get("/health")
def health():
    return {
        "status": "ok" if _state["loaded"] else "loading",
        "models_loaded": _state["loaded"],
        "supabase_connected": _supabase_available,
    }


@app.get("/")
def root():
    """Convenience redirect so http://localhost:8000/ takes you straight to
    the dashboard instead of a 404."""
    return RedirectResponse(url="/dashboard/")


@app.get("/metadata")
def metadata():
    if not _state["loaded"]:
        raise HTTPException(status_code=503, detail="Models not loaded yet")
    return _state["metadata"]


@app.post("/analyze")
def analyze(payload: dict):
    """
    Accepts either:
      - a single session record: {"protocol": "SMTP", "tls_version": "...", ...}
      - a batch: {"sessions": [ {...}, {...} ]}
    """
    if "sessions" in payload and isinstance(payload["sessions"], list):
        results = [_analyze_one(rec) for rec in payload["sessions"]]
    else:
        results = [_analyze_one(payload)]

    _persist_results(results)

    return {"count": len(results), "results": results}


@app.get("/history")
def history(limit: int = 50):
    """Return recent analysis results. Tries Supabase first, falls back to
    the in-memory cache if Supabase is unavailable."""
    if _supabase_available:
        try:
            items = sb_get_history(limit)
            return {"count": len(items), "results": items}
        except Exception as e:
            logger.error("Supabase history fetch failed, using in-memory: %s", e)

    # Fallback to in-memory
    items = list(HISTORY)[:limit]
    return {"count": len(items), "results": items}


@app.get("/stats")
def stats():
    """Aggregate statistics across all stored results — used by the
    dashboard summary cards."""
    if _supabase_available:
        try:
            return sb_get_stats()
        except Exception as e:
            logger.error("Supabase stats fetch failed, computing from memory: %s", e)

    # Fallback: compute from in-memory history
    items = list(HISTORY)
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    anomaly_count = 0
    score_sum = 0
    for r in items:
        rl = r.get("risk_level", "")
        if rl in risk_counts:
            risk_counts[rl] += 1
        if r.get("is_anomaly"):
            anomaly_count += 1
        score_sum += r.get("security_score", 0) or 0
    total = len(items)
    return {
        "total_count": total,
        "risk_counts": risk_counts,
        "avg_security_score": round(score_sum / total) if total else 0,
        "anomaly_count": anomaly_count,
    }


@app.post("/reload_models")
def reload_models():
    """Hot-reload models after re-running pipeline/train_models.py, without
    restarting the server."""
    load_models()
    return {"status": "reloaded"}


if __name__ == "__main__":
    # Lets you just do `python3 api/main.py` (run from the project root)
    # instead of typing the uvicorn command out.
    # For auto-reload during development, use instead:
    #   uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
