#!/usr/bin/env python3
"""
EMU API v2.0 — Vanguard Gateway Protobuf Builder
Protocol: AES-256-GCM encrypted envelopes
Returns a serialized AuthenticationRequest protobuf that vService
forwards to Riot's gateway.
"""
from flask import Flask, request, jsonify
import os, json, base64, hashlib, struct, time, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================
API_KEY = "12312a29db3b875bf98669d489c23e08d783f546e0352f222c3a638839fa6377"

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
# PROTOBUF helpers
# ============================================================
def _varint(n):
    buf = bytearray()
    while n > 0x7F:
        buf.append((n & 0x7F) | 0x80)
        n >>= 7
    buf.append(n & 0x7F)
    return bytes(buf)

def _tag(field, wire_type):
    return _varint((field << 3) | wire_type)

def _field_bytes(field, data):
    """Length-delimited field (wire type 2)"""
    if isinstance(data, str):
        data = data.encode()
    return _tag(field, 2) + _varint(len(data)) + data

# ============================================================
# PROTOBUF — AuthenticationRequest (reverse-engineered from vgc)
# Fields based on UC analysis:
#   1 = machine_id  (string)
#   3 = game_token  (string)        — JWT from Valorant
#   4 = machine_token (bytes)       — vgk.sys attestation (~1KB)
#   8 = game_id     (string)
#  11 = app_info    (string)
#  12 = device_info (string)
#  13 = session_id  (string)
# ============================================================
def construct_gateway_payload(gametoken, sid="", puuid=""):
    payload = bytearray()

    # Field 1 — machine_id: use puuid as machine_id if available
    machine_id = puuid if puuid else sid
    if machine_id:
        payload.extend(_field_bytes(1, machine_id))

    # Field 3 — game_token: the JWT from Valorant
    payload.extend(_field_bytes(3, gametoken))

    # Field 4 — machine_token: vgk.sys attestation placeholder
    # Real vgc sends ~1KB of attestation data here.
    # Without it, Riot may return 400. We'll try empty and see.
    # For now, send a small placeholder
    dummy_attestation = b"\x00" * 8
    payload.extend(_field_bytes(4, dummy_attestation))

    # Field 8 — game_id
    payload.extend(_field_bytes(8, "valorant"))

    # Field 11 — app_info
    payload.extend(_field_bytes(11, "1.18.2.24"))

    # Field 12 — device_info
    device_info = "Windows 10.0.19045"
    payload.extend(_field_bytes(12, device_info))

    # Field 13 — session_id
    if sid:
        payload.extend(_field_bytes(13, sid))

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

        # Construct AuthenticationRequest protobuf
        payload = construct_gateway_payload(gametoken, sid, puuid)

        # Return the protobuf as base64 "data" — vService will send it to Riot
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
                "data": base64.b64encode(payload).decode(),
                "session_id": session_id
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
    return jsonify({"status": "EMU API running", "version": "2.0"})

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 443))
    print(f"[EMU API v2] Baslatildi — Key: {API_KEY[:16]}...")
    print(f"[EMU API v2] Sunucu: http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
