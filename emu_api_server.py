#!/usr/bin/env python3
"""
EMU API v1.0 — Vanguard Gateway Proxy
Protocol: AES-256-GCM encrypted envelopes
"""
from flask import Flask, request, jsonify
import os, json, base64, hashlib, struct, time, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import urllib.request
import ssl

app = Flask(__name__)

# ============================================================
# CONFIG — bunu kendine gore degistir
# ============================================================
API_KEY = "12312a29db3b875bf98669d489c23e08d783f546e0352f222c3a638839fa6377"
REGION = "eu"  # eu / na / kr / ap / br / latam
# Riot gateway'e gonderirken kullanılacak X-VG header'lari
X_VG_1 = 3
X_VG_3 = 1

sessions = {}

# ============================================================
# CRYPTO
# ============================================================
def aes_key():
    return hashlib.sha256(API_KEY.encode()).digest()

def decrypt_envelope(body):
    d = base64.b64decode(body["d"])
    nonce, ct = d[:12], d[12:]
    pt = AESGCM(aes_key()).decrypt(nonce, ct, None)
    return json.loads(pt)

def encrypt_envelope(data):
    nonce = os.urandom(12)
    ct = AESGCM(aes_key()).encrypt(nonce, json.dumps(data, separators=(",", ":")).encode(), None)
    return base64.b64encode(nonce + ct).decode()

# ============================================================
# PROTOBUF — Vanguard gateway protokolü
# ============================================================
def _varint(n):
    """Protobuf varint encoding"""
    buf = bytearray()
    while n > 0x7F:
        buf.append((n & 0x7F) | 0x80)
        n >>= 7
    buf.append(n & 0x7F)
    return bytes(buf)

def _field_num(field, wire_type):
    return (field << 3) | wire_type

def _tag(field, wire_type):
    return _varint(_field_num(field, wire_type))

def _length_delimited(field, data):
    return _tag(field, 2) + _varint(len(data)) + (data if isinstance(data, bytes) else data.encode())

def _varint_field(field, value):
    return _tag(field, 0) + _varint(value)

def construct_gateway_payload(gametoken, puuid, sid=""):
    """
    Vanguard Gateway AuthRequest protobuf'u.
    Bilinen field'lar:
      1 = gametoken (string)
      2 = puuid (string)
      3 = sid (string)
      4 = attestation data (bytes) — vgk.sys'ten gelen ~1KB
      5 = timestamp (uint64)
      6 = platform (string) = "win32"
      7 = version (string) = "1.18.2-24"
    """
    payload = bytearray()
    payload.extend(_length_delimited(1, gametoken))
    if puuid:
        payload.extend(_length_delimited(2, puuid))
    if sid:
        payload.extend(_length_delimited(3, sid))
    # Attestation (field 4) — bos birak, riot gateway kabul eder mi bilinmez
    # Timestamp (field 5)
    ts = int(time.time() * 1000)
    payload.extend(_varint_field(5, ts))
    # Platform (field 6)
    payload.extend(_length_delimited(6, "win32"))
    # Version (field 7)
    payload.extend(_length_delimited(7, "1.18.2-24"))
    return bytes(payload)

# ============================================================
# ENDPOINTS
# ============================================================
@app.route("/vgc/session/gateway", methods=["POST"])
def gateway_auth():
    try:
        inner = decrypt_envelope(request.json)
        gametoken = inner["gametoken"]
        sid = inner.get("sid", "")
        puuid = inner.get("puuid", "")

        # Header'lardan region al veya varsayilani kullan
        region = request.headers.get("X-Region", REGION)
        host = f"{region}.vg.ac.pvp.net"

        # Protobuf yapisi
        payload = construct_gateway_payload(gametoken, puuid, sid)

        # X-VG header'lari
        headers = {
            "Content-Type": "application/x-protobuf",
            "User-Agent": "vanguard/1.18.2-24",
        }
        if puuid:
            headers["X-VG-2"] = puuid
        headers["X-VG-1"] = str(X_VG_1)
        headers["X-VG-3"] = str(X_VG_3)

        url = f"https://{host}:8443/vanguard/v1/gateway"
        req = urllib.request.Request(url, data=payload, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        riot_data = resp.read()

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "sid": sid,
            "puuid": puuid,
            "token": gametoken[:32],
            "created": time.time()
        }

        return jsonify({
            "d": encrypt_envelope({
                "success": True,
                "data": base64.b64encode(riot_data).decode(),
                "session_id": session_id
            })
        })
    except urllib.error.HTTPError as e:
        err_body = e.read()
        return jsonify({
            "d": encrypt_envelope({
                "success": False,
                "error": f"Riot gateway returned {e.code}",
                "raw": base64.b64encode(err_body).decode()
            })
        })
    except Exception as e:
        return jsonify({
            "d": encrypt_envelope({
                "success": False,
                "error": str(e)
            })
        })

@app.route("/vgc/session/access", methods=["POST"])
def session_access():
    try:
        inner = decrypt_envelope(request.json)
        sid = inner.get("session_id", "")
        resp_b64 = inner.get("response", "")
        if sid in sessions:
            sessions[sid]["access_response"] = resp_b64
        return jsonify({"d": encrypt_envelope({"success": True})})
    except Exception as e:
        return jsonify({"d": encrypt_envelope({"success": False, "error": str(e)})})

@app.route("/vgc/session/heartbeat", methods=["POST"])
def heartbeat():
    try:
        inner = decrypt_envelope(request.json)
        sid = inner.get("session_id", "")
        if sid in sessions:
            sessions[sid]["last_hb"] = time.time()
        return jsonify({"d": encrypt_envelope({"success": True})})
    except Exception:
        return jsonify({"d": encrypt_envelope({"success": True})})

@app.route("/vgc/session/tasks", methods=["POST"])
def tasks():
    return jsonify({"d": encrypt_envelope({"success": True, "tasks": []})})

@app.route("/")
def index():
    return jsonify({"status": "EMU API running", "version": "1.0"})

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 443))
    print(f"[EMU API] Baslatildi — Key: {API_KEY[:16]}...")
    print(f"[EMU API] Sunucu: http://0.0.0.0:{port}")
    print(f"[EMU API] Render SSL proxy HTTPS cevirir, burada HTTP yeter")
    app.run(host="0.0.0.0", port=port, debug=False)
