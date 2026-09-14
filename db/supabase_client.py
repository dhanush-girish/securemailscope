"""
Supabase client helpers for SecureMailScope.

Provides insert/query functions for the analysis_results table.
Uses the service-role key for server-side operations (bypasses RLS).

Usage:
    from db.supabase_client import insert_result, insert_results, get_history, get_stats
"""

import os
import logging
from typing import Optional

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

logger = logging.getLogger("securemailscope.db")

SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY: str = os.environ.get("SUPABASE_KEY", "")

TABLE = "analysis_results"

_client: Optional[Client] = None


def get_client() -> Client:
    """Lazy-initialize the Supabase client so import-time failures don't
    crash the entire API if env vars are missing."""
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_KEY must be set in environment / .env"
            )
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase client initialized for %s", SUPABASE_URL)
    return _client


def _row_from_result(result: dict) -> dict:
    """Map an API analysis result dict to a database row dict."""
    return {
        "result_id":           result.get("result_id"),
        "analyzed_at":         result.get("analyzed_at"),
        "session_id":          result.get("session_id"),
        "protocol":            result.get("protocol"),
        "tls_version":         result.get("tls_version"),
        "cipher_suite":        result.get("cipher_suite"),
        "risk_level":          result.get("risk_level"),
        "risk_confidence":     result.get("risk_confidence"),
        "class_probabilities": result.get("class_probabilities"),
        "is_anomaly":          int(result.get("is_anomaly")) if result.get("is_anomaly") is not None else 0,
        "anomaly_score":       result.get("anomaly_score"),
        "security_score":      result.get("security_score"),
        "detected_weaknesses": result.get("detected_weaknesses"),
        "recommendations":     result.get("recommendations"),
    }


def insert_result(result: dict) -> dict:
    """Insert a single analysis result. Returns the inserted row."""
    client = get_client()
    row = _row_from_result(result)
    response = client.table(TABLE).insert(row).execute()
    logger.debug("Inserted result %s", result.get("result_id"))
    return response.data[0] if response.data else row


def insert_results(results: list[dict]) -> list[dict]:
    """Batch-insert multiple analysis results. Returns inserted rows."""
    if not results:
        return []
    client = get_client()
    rows = [_row_from_result(r) for r in results]
    response = client.table(TABLE).insert(rows).execute()
    logger.debug("Inserted %d results", len(results))
    return response.data if response.data else rows


def get_history(limit: int = 50) -> list[dict]:
    """Fetch the most recent analysis results, ordered newest-first."""
    client = get_client()
    response = (
        client.table(TABLE)
        .select("*")
        .order("analyzed_at", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data or []


def get_stats() -> dict:
    """Compute aggregate statistics from all stored results.

    Returns a dict with total_count, risk_counts, avg_security_score,
    and anomaly_count.
    """
    client = get_client()

    # Fetch all rows (just the columns we need for aggregation).
    # For very large datasets you'd want a Postgres function instead,
    # but for the expected volume this is fine.
    response = (
        client.table(TABLE)
        .select("risk_level, security_score, is_anomaly")
        .execute()
    )
    rows = response.data or []

    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    anomaly_count = 0
    score_sum = 0

    for row in rows:
        rl = row.get("risk_level", "")
        if rl in risk_counts:
            risk_counts[rl] += 1
        if row.get("is_anomaly"):
            anomaly_count += 1
        score_sum += row.get("security_score", 0) or 0

    total = len(rows)
    return {
        "total_count": total,
        "risk_counts": risk_counts,
        "avg_security_score": round(score_sum / total) if total else 0,
        "anomaly_count": anomaly_count,
    }


def get_unprocessed_rows(limit: int = 50) -> list[dict]:
    """Fetch rows inserted by the cyber team that haven't been analyzed yet."""
    client = get_client()
    response = (
        client.table(TABLE)
        .select("*")
        .is_("risk_level", "null")
        .limit(limit)
        .execute()
    )
    return response.data or []


def update_row_ml_fields(row_id: int, ml_data: dict) -> dict:
    """Update a specific row with its Machine Learning analysis results."""
    client = get_client()
    # Map the ml_data cleanly to the expected columns
    update_payload = _row_from_result(ml_data)
    
    try:
        response = (
            client.table(TABLE)
            .update(update_payload)
            .eq("id", row_id)
            .execute()
        )
        return response.data[0] if response.data else update_payload
    except Exception as e:
        logger.error(f"Error updating row {row_id} in Supabase: {e}")
        logger.error(f"Update payload types: {{k: type(v).__name__ for k, v in update_payload.items()}}")
        logger.error(f"Update payload values: {update_payload}")
        raise
