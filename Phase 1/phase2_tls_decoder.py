"""
Phase 2 — SecureMailScope (v2)
Properly decodes TLS handshake fields (version, cipher suite name, certificate
details) from a .pcap file into a structured CSV.

Fixes over v1:
  1. Cipher suite codes are now resolved to readable names via a lookup table.
  2. TCP stream reassembly — packets are stitched back together in sequence order
     per direction before TLS parsing, so multi-packet messages (like most
     Certificate messages) are no longer silently dropped.

Install dependencies first:
  pip install scapy cryptography

Usage:
  python phase2_tls_decoder.py capture.pcap dataset.csv --label vulnerable
  python phase2_tls_decoder.py capture_good.pcap dataset.csv --label hardened
"""

import csv
import argparse
from datetime import datetime, timezone
from scapy.all import rdpcap, TCP, IP, Raw
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ── Cipher suite lookup table (code -> readable name) ───────────────────
# Covers the common weak, medium, and strong suites relevant to mail server audits.
CIPHER_SUITES = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0060: "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
    0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",       # TLS 1.3
    0x1302: "TLS_AES_256_GCM_SHA384",       # TLS 1.3
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", # TLS 1.3
    0x0000: "TLS_NULL_WITH_NULL_NULL",
}

VERSION_NAMES = {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
                  0x0303: "TLS1.2", 0x0304: "TLS1.3"}
DEPRECATED_VERSIONS = {"SSL3.0", "TLS1.0", "TLS1.1"}

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "CBC"]
NO_FORWARD_SECRECY_KEYWORDS = ["_RSA_WITH"]     # plain RSA key exchange (not ECDHE/DHE_RSA)
FORWARD_SECRET_KEYWORDS = ["ECDHE", "DHE"]


def cipher_name(code):
    if code is None:
        return "unknown"
    return CIPHER_SUITES.get(code, f"UNKNOWN_0x{code:04X}")


def decode_cert(cert_bytes: bytes) -> dict:
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        expiry = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        days_to_expiry = (expiry - datetime.now(timezone.utc)).days
        return {
            "cert_subject": cert.subject.rfc4514_string(),
            "cert_issuer": cert.issuer.rfc4514_string(),
            "cert_expiry": expiry.isoformat(),
            "cert_days_to_expiry": days_to_expiry,
            "cert_sig_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        }
    except Exception:
        return {"cert_subject": None, "cert_issuer": None, "cert_expiry": None,
                "cert_days_to_expiry": None, "cert_sig_algorithm": None}


def classify_flags(version_name, cname, cert_info):
    return {
        "flag_deprecated_version": version_name in DEPRECATED_VERSIONS,
        "flag_weak_cipher": any(w in cname for w in WEAK_CIPHER_KEYWORDS),
        "flag_no_forward_secrecy": (
            any(k in cname for k in NO_FORWARD_SECRECY_KEYWORDS)
            and not any(f in cname for f in FORWARD_SECRET_KEYWORDS)
        ),
        "flag_weak_cert_signature": bool(
            cert_info.get("cert_sig_algorithm") and
            any(a in cert_info["cert_sig_algorithm"].lower() for a in ["md5", "sha1"])
        ),
        "flag_cert_expiring_soon": bool(
            cert_info.get("cert_days_to_expiry") is not None and cert_info["cert_days_to_expiry"] < 30
        ),
    }


# ── TCP stream reassembly ────────────────────────────────────────────────
def reassemble_streams(packets):
    """
    Groups packets into per-direction byte streams, ordered by TCP sequence
    number, so multi-segment TLS messages (like Certificate) are reconstructed
    before parsing instead of being read one packet at a time.
    Returns: dict of (src_ip, src_port, dst_ip, dst_port) -> reassembled bytes
    """
    buckets = {}
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            continue
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        buckets.setdefault(key, []).append((pkt[TCP].seq, bytes(pkt[Raw].load)))

    streams = {}
    for key, segments in buckets.items():
        segments.sort(key=lambda s: s[0])
        seen_seqs = set()
        combined = b""
        for seq, payload in segments:
            if seq in seen_seqs:   # skip exact retransmissions
                continue
            seen_seqs.add(seq)
            combined += payload
        streams[key] = combined
    return streams


def find_tls_start(stream_bytes: bytes) -> int:
    """
    The plaintext SMTP conversation (220 ready, EHLO, STARTTLS...) shares the
    SAME TCP connection as the TLS handshake that follows it — they are not
    separate streams. So instead of assuming TLS starts at byte 0, scan forward
    for the first byte pattern that looks like a real TLS record header:
    content_type in {20,21,22,23}, version major byte 0x03, and a plausible length.
    Returns the byte offset where TLS actually begins, or -1 if never found.
    """
    n = len(stream_bytes)
    for i in range(n - 5):
        content_type = stream_bytes[i]
        if content_type not in (0x14, 0x15, 0x16, 0x17):
            continue
        if stream_bytes[i+1] != 0x03:          # TLS/SSL major version byte is always 0x03
            continue
        if stream_bytes[i+2] > 0x04:           # minor version: SSL3.0(0)..TLS1.3(4)
            continue
        length = (stream_bytes[i+3] << 8) | stream_bytes[i+4]
        if 0 < length <= 16384:                # max TLS record size
            return i
    return -1


def split_tls_records(stream_bytes: bytes):
    """
    Walks a reassembled byte stream and yields each individual TLS record's
    (content_type, version, body_bytes), using the 5-byte record header
    (type[1] + version[2] + length[2]) to find record boundaries correctly —
    this is what lets us pull out a Certificate message even if it spans
    what were originally several TCP packets.
    """
    start = find_tls_start(stream_bytes)
    if start == -1:
        return  # no TLS handshake found in this stream at all — plaintext only
    i = start
    n = len(stream_bytes)
    while i + 5 <= n:
        content_type = stream_bytes[i]
        if content_type not in (0x14, 0x15, 0x16, 0x17):  # not a valid TLS record type
            break
        version = (stream_bytes[i+1], stream_bytes[i+2])
        length = (stream_bytes[i+3] << 8) | stream_bytes[i+4]
        body_start = i + 5
        body_end = body_start + length
        if body_end > n:
            break  # incomplete record at the end of what we captured
        yield content_type, version, stream_bytes[body_start:body_end]
        i = body_end


def parse_handshake_body(content_type, body: bytes):
    """
    Minimal manual handshake-message parser (avoids depending on scapy's TLS
    contrib layer, which can vary in field names across versions).
    Only handles content_type 0x16 (handshake). Each handshake message inside
    a record starts with: msg_type[1] + length[3].
    """
    messages = []
    i = 0
    n = len(body)
    while i + 4 <= n:
        msg_type = body[i]
        msg_len = (body[i+1] << 16) | (body[i+2] << 8) | body[i+3]
        msg_body = body[i+4:i+4+msg_len]
        if len(msg_body) < msg_len:
            break
        messages.append((msg_type, msg_body))
        i += 4 + msg_len
    return messages


def parse_server_hello(body: bytes):
    # struct: version[2] + random[32] + session_id_len[1] + session_id[var]
    #         + cipher_suite[2] + compression_method[1] + extensions...
    #
    # BUG FIX: TLS 1.3 always sets this leading version[2] field to
    # {0x03, 0x03} ("TLS 1.2") for middlebox compatibility — the real
    # negotiated version is signaled separately, in a supported_versions
    # extension (type 0x002b) tacked onto the end of the ServerHello.
    # Reading only the leading field (as before) silently mislabels
    # every TLS 1.3 session as TLS 1.2. We now parse into the
    # extensions block and prefer supported_versions when present.
    if len(body) < 35:
        return None
    legacy_version = (body[0], body[1])
    session_id_len = body[34]
    offset = 35 + session_id_len
    if offset + 2 > len(body):
        return None
    cipher_code = (body[offset] << 8) | body[offset+1]
    offset += 2

    if offset + 1 > len(body):
        return {"version": legacy_version, "cipher_code": cipher_code}
    offset += 1  # skip compression_method byte

    real_version = legacy_version
    if offset + 2 <= len(body):
        ext_total_len = (body[offset] << 8) | body[offset+1]
        offset += 2
        ext_end = min(offset + ext_total_len, len(body))
        while offset + 4 <= ext_end:
            ext_type = (body[offset] << 8) | body[offset+1]
            ext_len = (body[offset+2] << 8) | body[offset+3]
            ext_data_start = offset + 4
            ext_data_end = ext_data_start + ext_len
            if ext_data_end > ext_end:
                break  # truncated/malformed extension, stop parsing extensions
            if ext_type == 0x002B and ext_len >= 2:  # supported_versions
                real_version = (body[ext_data_start], body[ext_data_start + 1])
            offset = ext_data_end

    return {"version": real_version, "cipher_code": cipher_code}


def parse_certificate_message(body: bytes):
    # struct: certificates_length[3] + [cert_length[3] + cert_bytes]...
    if len(body) < 3:
        return []
    certs = []
    total_len = (body[0] << 16) | (body[1] << 8) | body[2]
    i = 3
    end = 3 + total_len
    while i + 3 <= end and i + 3 <= len(body):
        cert_len = (body[i] << 16) | (body[i+1] << 8) | body[i+2]
        cert_bytes = body[i+3:i+3+cert_len]
        if len(cert_bytes) == cert_len:
            certs.append(cert_bytes)
        i += 3 + cert_len
    return certs


def extract_sessions(pcap_file: str) -> list[dict]:
    packets = rdpcap(pcap_file)
    streams = reassemble_streams(packets)
    rows = []

    for (src_ip, src_port, dst_ip, dst_port), stream_bytes in streams.items():
        server_hello_row = None
        for content_type, version, body in split_tls_records(stream_bytes):
            if content_type != 0x16:
                continue
            for msg_type, msg_body in parse_handshake_body(content_type, body):
                if msg_type == 2:  # ServerHello
                    parsed = parse_server_hello(msg_body)
                    if not parsed:
                        continue
                    version_name = VERSION_NAMES.get(
                        (parsed["version"][0] << 8) | parsed["version"][1], "unknown")
                    cname = cipher_name(parsed["cipher_code"])
                    server_hello_row = {
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "src_port": src_port, "dst_port": dst_port,
                        "negotiated_version": version_name,
                        "negotiated_cipher": cname,
                        "cert_subject": None, "cert_issuer": None, "cert_expiry": None,
                        "cert_days_to_expiry": None, "cert_sig_algorithm": None,
                    }
                    rows.append(server_hello_row)

                elif msg_type == 11 and server_hello_row is not None:  # Certificate
                    certs = parse_certificate_message(msg_body)
                    if certs:
                        cert_info = decode_cert(certs[0])
                        server_hello_row.update(cert_info)

    for row in rows:
        cert_info = {"cert_sig_algorithm": row["cert_sig_algorithm"],
                     "cert_days_to_expiry": row["cert_days_to_expiry"]}
        row.update(classify_flags(row["negotiated_version"], row["negotiated_cipher"], cert_info))

    return rows


def write_csv(rows, output_file, label):
    if not rows:
        print("No TLS ServerHello messages found — nothing to write.")
        return
    for row in rows:
        row["label"] = label

    fieldnames = list(rows[0].keys())
    try:
        with open(output_file, "r"):
            file_exists = True
    except FileNotFoundError:
        file_exists = False

    mode = "a" if file_exists else "w"
    with open(output_file, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} row(s) to {output_file} (label='{label}')")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decode TLS handshake fields from a pcap into a CSV.")
    parser.add_argument("pcap_file")
    parser.add_argument("output_csv")
    parser.add_argument("--label", default="unknown")
    args = parser.parse_args()

    rows = extract_sessions(args.pcap_file)
    print(f"Extracted {len(rows)} TLS session(s) from {args.pcap_file}")
    for r in rows:
        print(f"  {r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']}  "
              f"version={r['negotiated_version']}  cipher={r['negotiated_cipher']}  "
              f"weak_cipher={r['flag_weak_cipher']}  deprecated_version={r['flag_deprecated_version']}  "
              f"cert_subject={r['cert_subject']}")

    write_csv(rows, args.output_csv, args.label)
