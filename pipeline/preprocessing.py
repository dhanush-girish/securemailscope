"""
preprocessing.py

JSON -> clean -> validated -> numeric feature vector, in a way that is
IDENTICAL whether called during training or during live /analyze requests.

Design goals:
  1. Never crash on a missing/unexpected field. Real capture tools will not
     always populate everything (partial handshakes, STARTTLS never used,
     cert not observed, etc).
  2. Keep a single source of truth for "what does a weak cipher / old TLS /
     bad cert look like" as rule-based helper functions, so both the
     feature engineering AND the human-readable "weaknesses" / "recommendations"
     shown on the dashboard use the exact same logic.
  3. Be easy to re-point at real field names: edit FIELD_ALIASES below once
     you see your teammates' actual JSON output, nothing else needs to change.
"""

import re
import pandas as pd
import numpy as np
import joblib

# ---------------------------------------------------------------------------
# 1. FIELD ALIASES
# Updated 2026-09-12 against the real sample from the Ubuntu tool
# (dataset.csv). Real columns confirmed:
#   captured_at, src_ip, dst_ip, src_port, dst_port, negotiated_version,
#   negotiated_cipher, cert_subject, cert_issuer, cert_expiry,
#   cert_days_to_expiry, cert_sig_algorithm, flag_deprecated_version,
#   flag_weak_cipher, flag_no_forward_secrecy, flag_weak_cert_signature,
#   flag_cert_expiring_soon, label
#
# Notably: there is NO "protocol" field and NO "key_length" field in the real
# data. Protocol is inferred from src_port/dst_port below (see
# _infer_protocol_from_ports). key_exchange is inferred from the cipher
# suite name (see _parse_key_exchange_from_cipher) since it's embedded in
# strings like "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA". key_length has no real
# source at all currently -> stays unknown (-1), which the pipeline already
# handles gracefully.
# ---------------------------------------------------------------------------
FIELD_ALIASES = {
    "session_id": ["session_id", "id", "flow_id"],
    "captured_at": ["captured_at", "timestamp"],
    "protocol": ["protocol", "proto", "service"],  # usually absent -> inferred from ports
    "src_port": ["src_port"],
    "dst_port": ["dst_port", "port", "server_port"],
    "starttls_used": ["starttls_used", "starttls", "used_starttls"],
    "tls_version": ["tls_version", "tlsVersion", "ssl_version", "tls_ver", "negotiated_version"],
    "cipher_suite": ["cipher_suite", "cipherSuite", "cipher", "negotiated_cipher"],
    "key_exchange": ["key_exchange", "kex", "key_exchange_algo"],  # usually absent -> inferred from cipher
    "key_length": ["key_length", "keyLength", "key_size", "rsa_key_size"],
    "cert_expiry_days": ["cert_expiry_days", "cert_days_to_expiry", "days_to_expiry"],
    "cert_valid_to": ["cert_valid_to", "cert_not_after", "not_after", "cert_expiry"],
    "cert_sig_algorithm": ["cert_sig_algorithm", "cert_signature_algorithm"],
    "cert_self_signed": ["cert_self_signed", "self_signed", "is_self_signed"],
    "downgrade_attack_detected": ["downgrade_attack_detected", "downgrade_detected", "is_downgrade"],
    "mitm_indicators": ["mitm_indicators", "mitm_detected", "mitm_flag"],
    # Pre-computed flags the real tool already provides -- trusted directly
    # rather than re-derived, see _flag_true() below.
    "flag_deprecated_version": ["flag_deprecated_version"],
    "flag_weak_cipher": ["flag_weak_cipher"],
    "flag_no_forward_secrecy": ["flag_no_forward_secrecy"],
    "flag_weak_cert_signature": ["flag_weak_cert_signature"],
    "flag_cert_expiring_soon": ["flag_cert_expiring_soon"],
    # Ground-truth label, when the tool/dataset provides one.
    "label": ["label"],
}

REQUIRED_OUTPUT_FIELDS = list(FIELD_ALIASES.keys())

MAIL_PORTS = {
    25: "SMTP", 587: "SMTP", 2525: "SMTP",
    465: "SMTPS",
    143: "IMAP", 993: "IMAPS",
    110: "POP3", 995: "POP3S",
}

WEAK_SIG_ALGOS = {"md5", "sha1", "md5withrsa", "sha1withrsa"}



TLS_VERSION_SEVERITY = {
    "SSLv2": 0, "SSLv3": 0,
    "TLSv1.0": 1, "TLS1.0": 1, "TLSv1": 1,
    "TLSv1.1": 2, "TLS1.1": 2,
    "TLSv1.2": 3, "TLS1.2": 3,
    "TLSv1.3": 4, "TLS1.3": 4,
}
DEPRECATED_TLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLS1.0", "TLSv1", "TLSv1.1", "TLS1.1"}

WEAK_CIPHER_PATTERNS = [r"NULL", r"RC4", r"(^|_)DES(_|$)", r"3DES", r"EXPORT", r"MD5"]
STRONG_CIPHER_PATTERNS = [r"GCM", r"CHACHA20", r"POLY1305", r"CCM"]

KEY_EXCHANGE_SEVERITY = {"RSA": 0, "DH": 1, "DHE": 1, "ECDH": 2, "ECDHE": 2, "X25519": 2}

# ---------------------------------------------------------------------------
# Cipher suite decomposition into its 3 separate cryptographic algorithms.
# A name like TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 actually encodes THREE
# independent choices, each with its own risk:
#   1. Key exchange   (ECDHE)  -- how the session key gets negotiated
#   2. Authentication (ECDSA)  -- how the server proves its identity
#   3. Encryption     (AES_128_GCM) -- how the traffic itself is encrypted
# Each is checked independently below; if ANY ONE is weak/critical, the
# session is treated as vulnerable overall (see compute_security_score()).
# ---------------------------------------------------------------------------
KEX_RISK = {
    "ECDHE": "strong", "DHE": "strong",
    "DH": "weak", "ECDH": "weak",   # static (non-ephemeral) -- no forward secrecy
    "RSA": "weak",                  # static RSA key transport -- no forward secrecy
    "PSK": "medium",
    "ANON": "critical",
}
AUTH_RISK = {
    "RSA": "strong", "ECDSA": "strong",
    "DSS": "weak",                  # DSA-based signatures -- deprecated
    "PSK": "medium",
    "ANON": "critical",             # no certificate verification at all
}


def parse_cipher_suite(cipher):
    """
    Split a cipher suite name into its 3 independent algorithms.
    Handles both classic TLS 1.0-1.2 naming (TLS_{kex}_{auth}_WITH_{enc}_{mode}_{hash})
    and TLS 1.3 naming (TLS_{enc}_{mode}_{hash}, no kex/auth in the name --
    TLS 1.3 always negotiates ephemeral key exchange + cert-based auth
    separately, so those are treated as implicitly strong).
    Returns {"key_exchange": str|None, "authentication": str|None,
             "encryption": str|None, "mode": str|None, "hash": str|None,
             "is_tls13_style": bool}.
    """
    empty = {"key_exchange": None, "authentication": None, "encryption": None,
              "mode": None, "hash": None, "is_tls13_style": False}
    if not cipher or not isinstance(cipher, str):
        return empty

    c = cipher.upper()
    if c.startswith("TLS_"):
        c = c[4:]

    if "_WITH_" in c:
        pre, post = c.split("_WITH_", 1)
        pre_parts = [p for p in pre.split("_") if p]
        if len(pre_parts) == 1:
            kex = auth = pre_parts[0]
        elif len(pre_parts) >= 2:
            kex, auth = pre_parts[0], pre_parts[1]
        else:
            kex = auth = None
        is_tls13 = False
    else:
        post = c
        kex = auth = None
        is_tls13 = True

    post_parts = [p for p in post.split("_") if p]
    hash_ = post_parts[-1] if post_parts else None
    mode = next((p for p in post_parts if p in ("GCM", "CBC", "CCM8", "CCM", "POLY1305")), None)
    if mode and mode in post_parts:
        idx = post_parts.index(mode)
        encryption = "_".join(post_parts[:idx]) or mode
    else:
        encryption = "_".join(post_parts[:-1]) if len(post_parts) > 1 else (post_parts[0] if post_parts else None)

    return {
        "key_exchange": kex, "authentication": auth,
        "encryption": encryption, "mode": mode, "hash": hash_,
        "is_tls13_style": is_tls13,
    }


def _component_risks(cipher: str) -> dict:
    """Independent risk rating for each of the 3 algorithms, plus the
    encryption/mode combo. TLS 1.3 style suites are assumed strong for
    key-exchange/auth since TLS 1.3 mandates ephemeral exchange + removed
    anonymous/export ciphers entirely."""
    parsed = parse_cipher_suite(cipher)
    if parsed["is_tls13_style"]:
        kex_risk, auth_risk = "strong", "strong"
    else:
        kex_risk = KEX_RISK.get(parsed["key_exchange"], "unknown")
        auth_risk = AUTH_RISK.get(parsed["authentication"], "unknown")

    enc = (parsed["encryption"] or "")
    mode = (parsed["mode"] or "")
    enc_tokens = set(enc.upper().split("_")) | ({mode.upper()} if mode else set())
    if "NULL" in enc_tokens or "EXPORT" in enc_tokens:
        enc_risk = "critical"
    elif enc_tokens & {"RC4", "DES", "3DES"}:
        enc_risk = "weak"
    elif mode in ("GCM", "CCM", "CCM8", "POLY1305"):
        enc_risk = "strong"
    elif mode == "CBC":
        enc_risk = "medium"
    else:
        enc_risk = "unknown"

    return {
        "key_exchange": parsed["key_exchange"], "key_exchange_risk": kex_risk,
        "authentication": parsed["authentication"], "authentication_risk": auth_risk,
        "encryption": parsed["encryption"], "mode": parsed["mode"], "encryption_risk": enc_risk,
    }


def _get_field(record: dict, canonical_name: str):
    for alt in FIELD_ALIASES.get(canonical_name, [canonical_name]):
        if alt in record and record[alt] is not None:
            return record[alt]
    return None


def _infer_protocol_from_ports(src_port, dst_port):
    """The real tool doesn't send a 'protocol' field -- infer it from
    whichever side is a known mail port (25/587/465/143/993/110/995)."""
    for p in (src_port, dst_port):
        try:
            p_int = int(p)
        except (TypeError, ValueError):
            continue
        if p_int in MAIL_PORTS:
            return MAIL_PORTS[p_int]
    return None


def _is_tls13_style_cipher(cipher: str) -> bool:
    """TLS 1.3 cipher suite names (e.g. TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256) don't encode a key-exchange algorithm at
    all -- there's no "_WITH_" segment like older suites have
    (TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA). TLS 1.3 always negotiates an
    ephemeral (forward-secret) key exchange separately, so the absence of
    "ECDHE"/"DHE" in the name does NOT mean weak key exchange here -- it
    means the opposite. Detect these by the lack of a "_WITH_" segment.
    """
    return bool(cipher) and "_WITH_" not in cipher.upper()


def _parse_key_exchange_from_cipher(cipher):
    """The real tool doesn't send a 'key_exchange' field, but it's embedded
    in cipher suite names like TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA. TLS 1.3
    suite names (no "_WITH_") don't encode it -- TLS 1.3 always uses an
    ephemeral, forward-secret exchange, so we report ECDHE (the modern
    default) rather than "unknown"."""
    if not cipher or not isinstance(cipher, str):
        return None
    c = cipher.upper()
    if _is_tls13_style_cipher(c):
        return "ECDHE"
    if "ECDHE" in c:
        return "ECDHE"
    if "DHE" in c:
        return "DHE"
    if "ECDH" in c:
        return "ECDH"
    if "_RSA_" in c or c.startswith("TLS_RSA"):
        return "RSA"
    return None


def normalize_record(raw_record: dict) -> dict:
    """Map an arbitrary incoming JSON/CSV-row record onto our canonical field set,
    then fill in the fields the real tool doesn't send directly (protocol,
    key_exchange) via inference."""
    norm = {name: _get_field(raw_record, name) for name in REQUIRED_OUTPUT_FIELDS}
    if norm.get("protocol") is None:
        norm["protocol"] = _infer_protocol_from_ports(norm.get("src_port"), norm.get("dst_port"))
    if norm.get("key_exchange") is None:
        norm["key_exchange"] = _parse_key_exchange_from_cipher(norm.get("cipher_suite"))
    return norm


def _cipher_strength_score(cipher):
    if not cipher or not isinstance(cipher, str):
        return -1  # unknown
    c = cipher.upper()
    if any(re.search(p, c) for p in WEAK_CIPHER_PATTERNS):
        return 0
    if any(re.search(p, c) for p in STRONG_CIPHER_PATTERNS):
        return 2
    return 1  # e.g. CBC-mode AES with SHA - "medium"


def _tls_severity(version):
    if not version or not isinstance(version, str):
        return -1
    return TLS_VERSION_SEVERITY.get(version.strip(), -1)


def _is_deprecated_tls(version):
    return bool(version) and str(version).strip() in DEPRECATED_TLS


def _key_length_score(k):
    try:
        k = int(k)
    except (TypeError, ValueError):
        return -1
    if k < 1024:
        return 0
    if k < 2048:
        return 1
    if k < 4096:
        return 2
    return 3


def _key_exchange_score(kex):
    if not kex or not isinstance(kex, str):
        return -1
    return KEY_EXCHANGE_SEVERITY.get(kex.strip().upper(), -1)


def _cert_expiring_soon(expiry) -> bool:
    if expiry is None:
        return False
    try:
        return 0 <= float(expiry) < 15
    except (TypeError, ValueError):
        return False


def _to_int_bool(v, default=-1):
    """Coerce various truthy encodings (True/False/'true'/'yes'/1/0/None) to {-1,0,1}."""
    if v is None:
        return default
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return 1 if v else 0
    if isinstance(v, str):
        return 1 if v.strip().lower() in ("true", "yes", "1") else 0
    return default


def _flag_true(norm: dict, flag_name: str, fallback_bool: bool) -> bool:
    """Prefer the tool's own precomputed flag (flag_weak_cipher etc.) when
    present; fall back to our own derived heuristic only if the flag is
    absent (e.g. for synthetic data that doesn't have these flags)."""
    v = _to_int_bool(norm.get(flag_name), default=-1)
    if v == -1:
        return bool(fallback_bool)
    return bool(v)


def _is_weak_sig_algo(algo):
    if not algo or not isinstance(algo, str):
        return False
    return algo.strip().lower() in WEAK_SIG_ALGOS


def describe_weaknesses(norm: dict) -> list:
    """Human-readable weaknesses for the dashboard / recommendations.
    Prefers the tool's own precomputed flags (flag_deprecated_version etc.)
    when present, falling back to our own derived rules otherwise (e.g. for
    synthetic training data that predates the real flags). Also reports
    each of the 3 cipher-suite algorithms (key exchange, authentication,
    encryption) independently, per algorithm."""
    issues = []
    tls_version = norm.get("tls_version")
    cipher = norm.get("cipher_suite")
    key_len = norm.get("key_length")
    expiry = norm.get("cert_expiry_days")
    sig_algo = norm.get("cert_sig_algorithm")
    comp = _component_risks(cipher)

    if _flag_true(norm, "flag_deprecated_version", _is_deprecated_tls(tls_version)):
        issues.append(f"Deprecated TLS/SSL version in use ({tls_version or 'unknown'})")
    if tls_version is None:
        issues.append("TLS version could not be determined")
    if cipher is None:
        issues.append("Cipher suite could not be determined")

    # --- Component 1: key exchange ---
    if comp["key_exchange_risk"] == "critical":
        issues.append("Anonymous key exchange in use -- no server identity is verified at all (critical MITM risk)")
    elif _flag_true(norm, "flag_no_forward_secrecy", comp["key_exchange_risk"] == "weak"):
        issues.append(f"Non-forward-secret key exchange ({comp['key_exchange'] or 'unknown'}) in use")

    # --- Component 2: authentication ---
    if comp["authentication_risk"] == "critical":
        issues.append("Anonymous authentication in use -- client cannot verify server identity (critical MITM risk)")
    elif comp["authentication_risk"] == "weak":
        issues.append(f"Deprecated authentication algorithm ({comp['authentication']}) in use")

    # --- Component 3: encryption ---
    if _flag_true(norm, "flag_weak_cipher", comp["encryption_risk"] in ("weak", "critical")):
        if comp["encryption_risk"] == "critical":
            issues.append(f"Cipher suite provides no real encryption ({cipher or 'unknown'}) -- critical")
        else:
            issues.append(f"Weak/insecure encryption algorithm negotiated ({cipher or 'unknown'})")

    if _key_length_score(key_len) in (0, 1):
        issues.append(f"Weak key length ({key_len} bits)")
    if _flag_true(norm, "flag_weak_cert_signature", _is_weak_sig_algo(sig_algo)):
        issues.append(f"Weak certificate signature algorithm ({sig_algo or 'unknown'})")
    if norm.get("starttls_used") is False:
        issues.append("STARTTLS not used / opportunistic TLS not negotiated")
    if expiry is not None:
        try:
            if float(expiry) < 0:
                issues.append("TLS certificate has expired")
        except (TypeError, ValueError):
            pass
    if _flag_true(norm, "flag_cert_expiring_soon", _cert_expiring_soon(expiry)):
        issues.append(f"TLS certificate expiring soon ({expiry} days)" if expiry is not None else "TLS certificate expiring soon")
    if _to_int_bool(norm.get("cert_self_signed"), default=0) == 1:
        issues.append("Self-signed certificate in use")
    if _to_int_bool(norm.get("downgrade_attack_detected"), default=0) == 1:
        issues.append("Protocol downgrade attack indicators detected")
    if _to_int_bool(norm.get("mitm_indicators"), default=0) == 1:
        issues.append("Possible man-in-the-middle indicators detected")
    return issues


def recommend_actions(norm: dict) -> list:
    recs = []
    tls_version = norm.get("tls_version")
    cipher = norm.get("cipher_suite")
    expiry = norm.get("cert_expiry_days")
    sig_algo = norm.get("cert_sig_algorithm")
    comp = _component_risks(cipher)

    if _flag_true(norm, "flag_deprecated_version", _is_deprecated_tls(tls_version)) or tls_version is None:
        recs.append("Disable SSLv3/TLSv1.0/TLSv1.1; enforce TLSv1.2+ (prefer TLSv1.3).")
    if comp["key_exchange_risk"] == "critical" or comp["authentication_risk"] == "critical":
        recs.append("Disable anonymous cipher suites entirely; require certificate-based authentication.")
    if _flag_true(norm, "flag_no_forward_secrecy", comp["key_exchange_risk"] == "weak"):
        recs.append("Prefer ECDHE key exchange to provide forward secrecy.")
    if comp["authentication_risk"] == "weak":
        recs.append("Replace DSA/DSS-signed certificates with RSA or ECDSA.")
    if _flag_true(norm, "flag_weak_cipher", comp["encryption_risk"] in ("weak", "critical")):
        recs.append("Restrict cipher suites to AEAD ciphers (AES-GCM / ChaCha20-Poly1305).")
    if _key_length_score(norm.get("key_length")) in (0, 1):
        recs.append("Increase key length to at least 2048 bits (RSA) or use modern ECC.")
    if _flag_true(norm, "flag_weak_cert_signature", _is_weak_sig_algo(sig_algo)):
        recs.append("Reissue certificate using SHA-256 (or stronger) signature algorithm.")
    if norm.get("starttls_used") is False:
        recs.append("Enforce mandatory STARTTLS (reject plaintext fallback).")
    if _to_int_bool(norm.get("cert_self_signed"), default=0) == 1:
        recs.append("Replace self-signed certificate with one from a trusted CA.")
    if _flag_true(norm, "flag_cert_expiring_soon", _cert_expiring_soon(expiry)):
        recs.append("Renew TLS certificate immediately.")
    if _to_int_bool(norm.get("downgrade_attack_detected"), default=0) == 1:
        recs.append("Investigate possible downgrade attack; review firewall/IDS logs.")
    if _to_int_bool(norm.get("mitm_indicators"), default=0) == 1:
        recs.append("Investigate possible MITM activity; verify certificate pinning/DNS integrity.")
    if not recs:
        recs.append("No immediate action required; continue periodic monitoring.")
    return recs


# ---------------------------------------------------------------------------
# Security score: a transparent points-deduction system, NOT derived from
# the classifier's confidence. Every distinct weakness costs fixed points;
# more weaknesses raised = lower score, always. Start at 100, floor at 0.
# This is what "the score changes for each flag raised" means concretely.
# ---------------------------------------------------------------------------
SEVERITY_POINTS = {
    "deprecated_tls": 20,
    "unknown_tls_version": 8,
    "critical_key_exchange": 35,     # anonymous key exchange
    "weak_key_exchange": 15,         # static RSA/DH -- no forward secrecy
    "critical_authentication": 35,   # anonymous authentication
    "weak_authentication": 15,       # DSS/DSA
    "critical_encryption": 40,       # NULL / EXPORT-grade -- effectively no encryption
    "weak_encryption": 25,           # RC4 / DES / 3DES
    "unknown_cipher": 8,
    "weak_key_length": 15,
    "weak_cert_signature": 15,
    "cert_expired": 30,
    "cert_expiring_soon": 5,
    "cert_self_signed": 10,
    "downgrade_attack_detected": 30,
    "mitm_indicators": 35,
}


def compute_security_score(norm: dict) -> int:
    """0-100, 100 = best. Deducts fixed points per distinct weakness found;
    stacks additively so 3 weaknesses always score lower than 1."""
    tls_version = norm.get("tls_version")
    cipher = norm.get("cipher_suite")
    key_len = norm.get("key_length")
    expiry = norm.get("cert_expiry_days")
    sig_algo = norm.get("cert_sig_algorithm")
    comp = _component_risks(cipher)

    deductions = 0
    if _flag_true(norm, "flag_deprecated_version", _is_deprecated_tls(tls_version)):
        deductions += SEVERITY_POINTS["deprecated_tls"]
    elif tls_version is None:
        deductions += SEVERITY_POINTS["unknown_tls_version"]

    if comp["key_exchange_risk"] == "critical":
        deductions += SEVERITY_POINTS["critical_key_exchange"]
    elif _flag_true(norm, "flag_no_forward_secrecy", comp["key_exchange_risk"] == "weak"):
        deductions += SEVERITY_POINTS["weak_key_exchange"]

    if comp["authentication_risk"] == "critical":
        deductions += SEVERITY_POINTS["critical_authentication"]
    elif comp["authentication_risk"] == "weak":
        deductions += SEVERITY_POINTS["weak_authentication"]

    if _flag_true(norm, "flag_weak_cipher", comp["encryption_risk"] in ("weak", "critical")):
        if comp["encryption_risk"] == "critical":
            deductions += SEVERITY_POINTS["critical_encryption"]
        else:
            deductions += SEVERITY_POINTS["weak_encryption"]
    elif cipher is None:
        deductions += SEVERITY_POINTS["unknown_cipher"]

    if _key_length_score(key_len) in (0, 1):
        deductions += SEVERITY_POINTS["weak_key_length"]
    if _flag_true(norm, "flag_weak_cert_signature", _is_weak_sig_algo(sig_algo)):
        deductions += SEVERITY_POINTS["weak_cert_signature"]

    if expiry is not None:
        try:
            if float(expiry) < 0:
                deductions += SEVERITY_POINTS["cert_expired"]
        except (TypeError, ValueError):
            pass
    if _flag_true(norm, "flag_cert_expiring_soon", _cert_expiring_soon(expiry)):
        deductions += SEVERITY_POINTS["cert_expiring_soon"]
    if _to_int_bool(norm.get("cert_self_signed"), default=0) == 1:
        deductions += SEVERITY_POINTS["cert_self_signed"]
    if _to_int_bool(norm.get("downgrade_attack_detected"), default=0) == 1:
        deductions += SEVERITY_POINTS["downgrade_attack_detected"]
    if _to_int_bool(norm.get("mitm_indicators"), default=0) == 1:
        deductions += SEVERITY_POINTS["mitm_indicators"]

    return max(0, min(100, 100 - deductions))


def engineer_features(norm: dict) -> dict:
    """Turn a normalized record into a flat numeric feature dict."""
    expiry = norm.get("cert_expiry_days")
    try:
        expiry = float(expiry) if expiry is not None else np.nan
    except (TypeError, ValueError):
        expiry = np.nan

    protocol = (norm.get("protocol") or "UNKNOWN").upper()
    implicit_tls = protocol in ("SMTPS", "IMAPS", "POP3S")

    missing_count = sum(
        1 for k in ["tls_version", "cipher_suite", "key_exchange", "key_length", "cert_expiry_days"]
        if norm.get(k) is None
    )

    comp = _component_risks(norm.get("cipher_suite"))
    risk_num = {"strong": 2, "medium": 1, "weak": 0, "critical": -1, "unknown": -2}

    feats = {
        "protocol": protocol,
        "implicit_tls": int(implicit_tls),
        "starttls_used": _to_int_bool(norm.get("starttls_used")),
        "tls_severity": _tls_severity(norm.get("tls_version")),
        "is_deprecated_tls": int(_flag_true(norm, "flag_deprecated_version", _is_deprecated_tls(norm.get("tls_version")))),
        "cipher_strength": _cipher_strength_score(norm.get("cipher_suite")),
        "weak_cipher_flag": int(_flag_true(norm, "flag_weak_cipher", comp["encryption_risk"] in ("weak", "critical"))),
        "key_exchange_score": _key_exchange_score(norm.get("key_exchange")),
        "key_exchange_risk_num": risk_num.get(comp["key_exchange_risk"], -2),
        "authentication_risk_num": risk_num.get(comp["authentication_risk"], -2),
        "encryption_risk_num": risk_num.get(comp["encryption_risk"], -2),
        "no_forward_secrecy_flag": int(_flag_true(norm, "flag_no_forward_secrecy", comp["key_exchange_risk"] == "weak")),
        "key_length_score": _key_length_score(norm.get("key_length")),
        "cert_sig_weak": int(_flag_true(norm, "flag_weak_cert_signature", _is_weak_sig_algo(norm.get("cert_sig_algorithm")))),
        "cert_expiry_days": expiry,
        "cert_expired": int(expiry < 0) if not np.isnan(expiry) else -1,
        "cert_expiring_soon": int(_flag_true(norm, "flag_cert_expiring_soon", _cert_expiring_soon(expiry))),
        "cert_self_signed": _to_int_bool(norm.get("cert_self_signed")),
        "downgrade_attack_detected": _to_int_bool(norm.get("downgrade_attack_detected")),
        "mitm_indicators": _to_int_bool(norm.get("mitm_indicators")),
        "missing_field_count": missing_count,
    }
    return feats


NUMERIC_FEATURES = [
    "implicit_tls", "starttls_used", "tls_severity", "is_deprecated_tls",
    "cipher_strength", "weak_cipher_flag", "key_exchange_score",
    "key_exchange_risk_num", "authentication_risk_num", "encryption_risk_num",
    "no_forward_secrecy_flag", "key_length_score", "cert_sig_weak",
    "cert_expiry_days", "cert_expired", "cert_expiring_soon",
    "cert_self_signed", "downgrade_attack_detected", "mitm_indicators",
    "missing_field_count",
]
CATEGORICAL_FEATURES = ["protocol"]


def records_to_feature_df(raw_records: list) -> pd.DataFrame:
    """Full pipeline stage: list of raw JSON dicts -> feature DataFrame (pre-encoding)."""
    rows = []
    for r in raw_records:
        norm = normalize_record(r)
        feats = engineer_features(norm)
        rows.append(feats)
    return pd.DataFrame(rows, columns=NUMERIC_FEATURES + CATEGORICAL_FEATURES)


class SecureMailPreprocessor:
    """
    Wraps a sklearn ColumnTransformer (imputation + one-hot protocol encoding)
    so the SAME fitted transform is used at train time and inference time.
    Save/load via joblib.
    """

    def __init__(self, column_transformer, feature_names_out):
        self.column_transformer = column_transformer
        self.feature_names_out = feature_names_out

    def transform_raw(self, raw_records: list) -> np.ndarray:
        df = records_to_feature_df(raw_records)
        return self.column_transformer.transform(df)

    def save(self, path):
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        return joblib.load(path)
