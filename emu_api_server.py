#!/usr/bin/env python3
"""
EMU API v2.1 — Returns multiple protobuf formats for vService to try
"""
from flask import Flask, request, jsonify
import os, json, base64, hashlib, time, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

API_KEY = "12312a29db3b875bf98669d489c23e08d783f546e0352f222c3a638839fa6377"
sessions = {}

def aes_key():
    return hashlib.sha256(API_KEY.encode()).digest()

def decrypt_envelope(body):
    d = base64.b64decode(body["d"])
    pt = AESGCM(aes_key()).decrypt(d[:12], d[12:], None)
    return json.loads(pt)

def encrypt_envelope(data):
    nonce = os.urandom(12)
    ct = AESGCM(aes_key()).encrypt(nonce, json.dumps(data, separators=(",", ":")).encode(), None)
    return base64.b64encode(nonce + ct).decode()

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
    if isinstance(data, str):
        data = data.encode()
    return _tag(field, 2) + _varint(len(data)) + data

def _varint_field(field, value):
    return _tag(field, 0) + _varint(value)

def build_format_1(gametoken, puuid, sid):
    """Format 1: field 1 = JWT"""
    return _field_bytes(1, gametoken)

def build_format_2(gametoken, puuid, sid):
    """Format 2: field 1 = JWT, field 2 = puuid"""
    p = bytearray()
    p.extend(_field_bytes(1, gametoken))
    if puuid:
        p.extend(_field_bytes(2, puuid))
    return bytes(p)

def build_format_3(gametoken, puuid, sid):
    """Format 3: field 1 = JWT, field 2 = puuid, field 3 = sid"""
    p = bytearray()
    p.extend(_field_bytes(1, gametoken))
    if puuid:
        p.extend(_field_bytes(2, puuid))
    if sid:
        p.extend(_field_bytes(3, sid))
    return bytes(p)

def build_format_4(gametoken, puuid, sid):
    """Format 4: field 1 = puuid, field 2 = JWT"""
    p = bytearray()
    if puuid:
        p.extend(_field_bytes(1, puuid))
    p.extend(_field_bytes(2, gametoken))
    if sid:
        p.extend(_field_bytes(3, sid))
    return bytes(p)

def build_format_5(gametoken, puuid, sid):
    """Format 5: Envelope(type=3, payload=field1=JWT)"""
    inner = _field_bytes(1, gametoken)
    return _varint_field(1, 3) + _field_bytes(2, inner)

def build_format_6(gametoken, puuid, sid):
    """Format 6: AuthRequest with machine_id, game_token, machine_token, game_id, app_info, device_info, session_id"""
    p = bytearray()
    p.extend(_field_bytes(1, puuid if puuid else "unknown"))
    p.extend(_field_bytes(3, gametoken))
    p.extend(_field_bytes(4, os.urandom(16)))
    p.extend(_field_bytes(8, "valorant"))
    p.extend(_field_bytes(11, "1.18.2.24"))
    p.extend(_field_bytes(12, "Windows 10.0.19045"))
    if sid:
        p.extend(_field_bytes(13, sid))
    return bytes(p)

@app.route("/vgc/session/gateway", methods=["POST"])
def gateway_auth():
    try:
        inner = decrypt_envelope(request.json)
        gametoken = inner["gametoken"]
        sid = inner.get("sid", "")
        puuid = inner.get("puuid", "")

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "sid": sid, "puuid": puuid,
            "token": gametoken[:32], "created": time.time()
        }

        # Return format 3 (JWT + puuid + sid) as "data"
        payload = build_format_3(gametoken, puuid, sid)

        return jsonify({
            "d": encrypt_envelope({
                "success": True,
                "data": base64.b64encode(payload).decode(),
                "session_id": session_id
            })
        })
    except Exception as e:
        return jsonify({
            "d": encrypt_envelope({"success": False, "error": str(e)})
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
    return jsonify({"status": "EMU API running", "version": "2.1"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 443))
    print(f"[EMU API v2.1] Baslatildi — Key: {API_KEY[:16]}...")
    app.run(host="0.0.0.0", port=port, debug=False)
