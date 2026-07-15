#!/usr/bin/env python3
"""
EMU API v2.0 — Vanguard Gateway Protobuf Builder
Protocol: AES-256-GCM encrypted envelopes
Returns a serialized AuthenticationRequest protobuf that vService
forwards to Riot's gateway.
"""
from flask import Flask, request, jsonify
import os, json, base64, hashlib, struct, time, uuid, urllib.request, ssl
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
    if isinstance(data, str):
        data = data.encode()
    return _tag(field, 2) + _varint(len(data)) + data

def _varint_field(field, value):
    return _tag(field, 0) + _varint(value)

# ============================================================
# PROTOBUF — Envelope wrapping AuthenticationRequest
#
# Envelope {
#   MessageType type = 1;  // AUTH_REQUEST = 3
#   bytes payload = 2;     // serialized AuthenticationRequest
# }
#
# AuthenticationRequest fields (from UC vgc analysis):
#   1 = machine_id    (string)
#   3 = game_token    (string) — JWT from Valorant
#   4 = machine_token (bytes)  — vgk.sys attestation
#   8 = game_id       (string)
#  11 = app_info      (string)
#  12 = device_info   (string)
#  13 = session_id    (string)
# ============================================================
def build_auth_request(gametoken, sid="", puuid=""):
    req = bytearray()

    mid = puuid if puuid else sid
    if mid:
        req.extend(_field_bytes(1, mid))
    req.extend(_field_bytes(3, gametoken))
    # field 4: machine_token placeholder (real vgk attestation ~1KB, we send 16 bytes)
    req.extend(_field_bytes(4, os.urandom(16)))
    req.extend(_field_bytes(8, "valorant"))
    req.extend(_field_bytes(11, "1.18.2.24"))
    req.extend(_field_bytes(12, "Windows 10.0.19045"))
    if sid:
        req.extend(_field_bytes(13, sid))

    return bytes(req)

# ============================================================
# Try multiple protobuf formats against Riot's gateway
# ============================================================
def try_riot_gateway(host, gametoken, sid, puuid):
    """Try different protobuf formats until one works (returns 200)."""

    auth_req = build_auth_request(gametoken, sid, puuid)

    formats = [
        # Format 1: Raw AuthenticationRequest (no wrapper)
        ("raw_auth_request", auth_req),
        # Format 2: Envelope(type=3, payload=AuthRequest)
        ("envelope_wrapped", _varint_field(1, 3) + _field_bytes(2, auth_req)),
        # Format 3: Just the JWT in field 1 (minimal)
        ("minimal_jwt", _field_bytes(1, gametoken)),
    ]

    url = f"https://{host}:8443/vanguard/v1/gateway"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for fmt_name, payload in formats:
        headers = {
            "Content-Type": "application/x-protobuf",
            "User-Agent": "vanguard/1.18.2-24",
            "X-VG-1": "3",
            "X-VG-3": "1",
        }
        if puuid:
            headers["X-VG-2"] = puuid

        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            resp = urllib.request.urlopen(req, context=ctx, timeout=15)
            riot_data = resp.read()
            print(f"[GATEWAY] {fmt_name}: HTTP 200 — {len(riot_data)} bytes")
            return True, payload, riot_data
        except urllib.error.HTTPError as e:
            err = e.read()
            status = e.code
            code_hex = err[:64].hex() if err else "empty"
            print(f"[GATEWAY] {fmt_name}: HTTP {status} — {code_hex}")
            # If 401, format is correct but token is invalid — still valid format
            if status == 401:
                print(f"[GATEWAY] {fmt_name}: got 401 (format accepted!)")
                return True, payload, err
            continue
        except Exception as e:
            print(f"[GATEWAY] {fmt_name}: exception {e}")
            continue

    return False, None, None

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

        region = request.headers.get("X-Region", "eu")
        host = f"{region}.vg.ac.pvp.net"

        # Try different protobuf formats against Riot's gateway
        ok, payload, riot_response = try_riot_gateway(host, gametoken, sid, puuid)

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "sid": sid, "puuid": puuid,
            "token": gametoken[:32], "created": time.time()
        }

        if ok:
            # Return the SAME payload as "data" so vService forwards it to Riot
            # If riot_response came from Riot, vService sends it and gets echo 200
            return jsonify({
                "d": encrypt_envelope({
                    "success": True,
                    "data": base64.b64encode(payload).decode(),
                    "session_id": session_id
                })
            })
        else:
            return jsonify({
                "d": encrypt_envelope({
                    "success": False,
                    "error": "all protobuf formats failed against Riot gateway"
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
