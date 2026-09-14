"""
send_session.py

Alternative to watch_and_forward.py: a single reusable function your
teammates can import directly into their (Python) Ubuntu-side capture tool,
if they're available to add a couple of lines. Lower latency than file
watching -- sends each session the instant it's built, no polling.

USAGE (inside their tool, wherever they currently build a session dict
before writing it to CSV):

    from send_session import send_session

    record = {
        "captured_at": ..., "src_ip": ..., "dst_ip": ...,
        "src_port": 25, "dst_port": 51234,
        "negotiated_version": "TLS1.2",
        "negotiated_cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "cert_days_to_expiry": 200,
        "cert_sig_algorithm": "sha256",
        "flag_deprecated_version": False,
        "flag_weak_cipher": False,
        "flag_no_forward_secrecy": False,
        "flag_weak_cert_signature": False,
        "flag_cert_expiring_soon": False,
        "label": "hardened",
    }
    result = send_session(record)   # <-- the one new line
    # keep writing to CSV as before, this doesn't replace that

send_session() never raises -- if the API is unreachable it logs a warning
and returns None, so it can't crash their capture tool.
"""

import requests

DEFAULT_API_URL = "http://localhost:8000/analyze"


def send_session(record: dict, api_url: str = DEFAULT_API_URL, timeout: float = 5.0) -> dict | None:
    """POST one session record to FastAPI's /analyze and return the parsed
    result dict (risk_level, security_score, detected_weaknesses,
    recommendations, ...), or None if the request failed."""
    try:
        resp = requests.post(api_url, json=record, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return data["results"][0] if data.get("results") else None
    except requests.exceptions.RequestException as e:
        print(f"[send_session] Could not reach SecureMailScope API at {api_url}: {e}")
        return None


def send_batch(records: list, api_url: str = DEFAULT_API_URL, timeout: float = 5.0) -> list | None:
    """Same idea, but for a batch of session records at once (fewer HTTP
    round-trips if the tool builds many sessions per capture run)."""
    try:
        resp = requests.post(api_url, json={"sessions": records}, timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("results", [])
    except requests.exceptions.RequestException as e:
        print(f"[send_session] Could not reach SecureMailScope API at {api_url}: {e}")
        return None


if __name__ == "__main__":
    # Quick smoke test: python integration/send_session.py
    test_record = {
        "src_port": 25, "negotiated_version": "TLS1.0",
        "negotiated_cipher": "TLS_RSA_WITH_RC4_128_SHA",
        "cert_days_to_expiry": 10, "cert_sig_algorithm": "sha1",
        "flag_deprecated_version": True, "flag_weak_cipher": True,
        "flag_no_forward_secrecy": True, "flag_weak_cert_signature": False,
        "flag_cert_expiring_soon": True,
    }
    result = send_session(test_record)
    print(result)
