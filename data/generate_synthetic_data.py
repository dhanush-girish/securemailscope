"""
generate_synthetic_data.py

Generates synthetic session records matching the REAL schema confirmed from
the Ubuntu tool's actual CSV export (dataset.csv, received 2026-09-12):

    captured_at, src_ip, dst_ip, src_port, dst_port,
    negotiated_version, negotiated_cipher,
    cert_subject, cert_issuer, cert_expiry, cert_days_to_expiry,
    cert_sig_algorithm,
    flag_deprecated_version, flag_weak_cipher, flag_no_forward_secrecy,
    flag_weak_cert_signature, flag_cert_expiring_soon,
    label

ASSUMPTION ABOUT `label` (flag this to your teammates and fix if wrong):
------------------------------------------------------------------------
The only real example we have is a single row labeled "vulnerable". We do
NOT know the real tool's full label taxonomy yet -- it might be binary
(secure/vulnerable), it might have severity tiers, it might be something
else entirely. Until you can confirm this with your teammates, this
generator makes the simplest possible assumption:

    label = "vulnerable" if ANY of the 5 flag_* columns is True, else "secure"

This is a defensible default (it mirrors how the one real row was labeled:
flag_weak_cipher=True -> label="vulnerable"), and it's a single line to
change below (see `derive_label()`) once you know more. Everything else in
the pipeline (train_models.py's get_label(), the API, the dashboard)
already reads whatever label values exist -- nothing else needs to change
if you switch to a different taxonomy, e.g. adding a "critical" tier.
"""

import json
import random
import os
from datetime import datetime, timedelta, timezone

# Ports actually used as one side of the connection for each protocol.
# The real tool doesn't send a "protocol" field -- it's inferred from these
# well-known ports (see _infer_protocol_from_ports in preprocessing.py).
SERVER_PORTS = {
    "SMTP": 25, "SMTP_SUBMISSION": 587,
    "SMTPS": 465,
    "IMAP": 143, "IMAPS": 993,
    "POP3": 110, "POP3S": 995,
}

TLS_VERSIONS_SECURE = ["TLS1.2", "TLS1.3"]
TLS_VERSIONS_WEAK = ["TLS1.0", "TLS1.1", "SSLv3"]

CIPHERS_STRONG = [  # AEAD, forward-secret
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
]
CIPHERS_MEDIUM = [  # forward-secret but CBC-mode (not AEAD)
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
]
CIPHERS_WEAK = [  # no forward secrecy and/or legacy/broken
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_WITH_NULL_SHA",
]

CERT_ISSUERS = ["DigiCert", "Let's Encrypt", "SecureMailScope-Legit", "Self-Signed-CA"]
SIG_ALGOS_STRONG = ["sha256", "sha384"]
SIG_ALGOS_WEAK = ["sha1", "md5"]


def _rand_bool(p_true=0.5):
    return random.random() < p_true


def _random_ip(octet_range=(0, 255)):
    return f"10.{random.randint(*octet_range)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _make_record(force_profile=None):
    """
    force_profile in {"secure", "weak", "critical", None} biases generation
    so the dataset has a controllable mix of postures. "None" draws from a
    realistic weighted mix.
    """
    profile = force_profile or random.choices(
        ["secure", "weak", "critical", "mixed"],
        weights=[0.40, 0.25, 0.15, 0.20],
    )[0]

    protocol_name = random.choice(list(SERVER_PORTS.keys()))
    server_port = SERVER_PORTS[protocol_name]
    client_port = random.randint(1024, 65000)
    # Real capture shows server port as src_port when the server->client
    # direction was captured; keep this randomized so both orderings appear,
    # matching the one real sample we have (src_port=25 was the server side).
    if _rand_bool(0.5):
        src_port, dst_port = server_port, client_port
    else:
        src_port, dst_port = client_port, server_port

    if profile == "secure":
        tls_version = random.choice(TLS_VERSIONS_SECURE)
        cipher = random.choice(CIPHERS_STRONG)
        cert_days_to_expiry = random.randint(30, 365)
        cert_issuer = random.choice(["DigiCert", "Let's Encrypt"])
        sig_algo = random.choice(SIG_ALGOS_STRONG)
    elif profile == "weak":
        tls_version = random.choice(TLS_VERSIONS_SECURE + ["TLS1.1"])
        cipher = random.choice(CIPHERS_MEDIUM)
        cert_days_to_expiry = random.randint(-5, 60)
        cert_issuer = random.choice(CERT_ISSUERS)
        sig_algo = random.choice(SIG_ALGOS_STRONG + ["sha1"])
    elif profile == "critical":
        tls_version = random.choice(TLS_VERSIONS_WEAK)
        cipher = random.choice(CIPHERS_WEAK)
        cert_days_to_expiry = random.randint(-90, 10)
        cert_issuer = random.choice(["Self-Signed-CA", "Self-Signed-CA"])
        sig_algo = random.choice(SIG_ALGOS_WEAK)
    else:  # mixed - noisy middle, most realistic for "unsure" cases
        tls_version = random.choice(TLS_VERSIONS_SECURE + TLS_VERSIONS_WEAK)
        cipher = random.choice(CIPHERS_STRONG + CIPHERS_MEDIUM + CIPHERS_WEAK)
        cert_days_to_expiry = random.randint(-30, 200)
        cert_issuer = random.choice(CERT_ISSUERS)
        sig_algo = random.choice(SIG_ALGOS_STRONG + SIG_ALGOS_WEAK)

    # Occasionally simulate a partial/incomplete capture (real tools won't
    # always see everything -- handshake truncated, session too short, etc.)
    if _rand_bool(0.05):
        tls_version = None
    if _rand_bool(0.05):
        cipher = None
    if _rand_bool(0.08):
        cert_days_to_expiry = None
    if _rand_bool(0.05):
        sig_algo = None

    # Flags: the real tool computes these itself. Derive them the same way
    # it plausibly would, from the fields above.
    flag_deprecated_version = tls_version in ("TLS1.0", "TLS1.1", "SSLv3") if tls_version else True
    flag_weak_cipher = cipher in CIPHERS_WEAK if cipher else True
    flag_no_forward_secrecy = bool(
        cipher and "_WITH_" in cipher and "ECDHE" not in cipher and "DHE" not in cipher
    )
    # TLS 1.3 style suites (no "_WITH_") always negotiate an ephemeral,
    # forward-secret exchange -- never flag those as lacking forward secrecy.
    flag_weak_cert_signature = sig_algo in ("sha1", "md5") if sig_algo else True
    flag_cert_expiring_soon = (
        cert_days_to_expiry is not None and 0 <= cert_days_to_expiry < 15
    )

    ts = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 60 * 24 * 7))

    record = {
        "captured_at": ts.isoformat(),
        "src_ip": _random_ip(),
        "dst_ip": _random_ip(),
        "src_port": src_port,
        "dst_port": dst_port,
        "negotiated_version": tls_version,
        "negotiated_cipher": cipher,
        "cert_subject": f"CN=mail{random.randint(1,50)}.securemailscope.local,O=SecureMailScope,ST=KL,C=IN",
        "cert_issuer": cert_issuer,
        "cert_expiry": (ts + timedelta(days=cert_days_to_expiry)).isoformat() if cert_days_to_expiry is not None else None,
        "cert_days_to_expiry": cert_days_to_expiry,
        "cert_sig_algorithm": sig_algo,
        "flag_deprecated_version": flag_deprecated_version,
        "flag_weak_cipher": flag_weak_cipher,
        "flag_no_forward_secrecy": flag_no_forward_secrecy,
        "flag_weak_cert_signature": flag_weak_cert_signature,
        "flag_cert_expiring_soon": flag_cert_expiring_soon,
    }
    record["label"] = derive_label(record)
    return record


def derive_label(record: dict) -> str:
    """
    *** THE ASSUMPTION TO REVISIT ONCE YOU HEAR BACK FROM YOUR TEAMMATES ***
    Binary label: "vulnerable" if any weakness flag fired, else "hardened".
    *** Confirmed against real data 2026-09-13: sessions_export.csv uses
    "hardened" (not "secure") as the clean-session label. ***
    """
    any_flag = any([
        record["flag_deprecated_version"],
        record["flag_weak_cipher"],
        record["flag_no_forward_secrecy"],
        record["flag_weak_cert_signature"],
        record["flag_cert_expiring_soon"],
    ])
    return "vulnerable" if any_flag else "hardened"


def generate_dataset(n=2500, seed=42):
    random.seed(seed)
    return [_make_record() for _ in range(n)]


if __name__ == "__main__":
    data = generate_dataset(2500)
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic_dataset.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote {len(data)} synthetic records to {out_path}")

    from collections import Counter
    print("Label distribution:", Counter(d["label"] for d in data))
