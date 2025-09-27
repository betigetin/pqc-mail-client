# # backend/routes.py
# from flask import Blueprint, request, jsonify, current_app, g
# from backend import db
# from backend.models import User, Device, Message
# from backend.crypto_utils import sha256_hex, hash_password, verify_password
# import json
# import base64
# from nacl.signing import VerifyKey
# from nacl.encoding import RawEncoder
# from datetime import datetime, timedelta
# import jwt
# from functools import wraps

# api = Blueprint('api', __name__)

# # ---------------------------
# # JWT helpers and auth decorator
# # ---------------------------
# def create_token(email_hash: str, minutes_valid: int = 120) -> str:
#     payload = {
#         "sub": email_hash,
#         "exp": datetime.utcnow() + timedelta(minutes=minutes_valid),
#         "iat": datetime.utcnow()
#     }
#     token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
#     # PyJWT 2.x returns str
#     if isinstance(token, bytes):
#         token = token.decode()
#     return token

# def decode_token(token: str):
#     try:
#         payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
#         return payload
#     except jwt.ExpiredSignatureError:
#         return None
#     except jwt.InvalidTokenError:
#         return None

# def auth_required(fn):
#     """
#     Decorator that sets g.user (User model) if auth succeeds.
#     Accepts:
#      - Authorization: Bearer <token>  (preferred)
#      - Or fallback: JSON body with 'email' & 'password'
#     """
#     @wraps(fn)
#     def wrapper(*args, **kwargs):
#         # Try Bearer token first
#         auth_header = request.headers.get("Authorization", "")
#         if auth_header.startswith("Bearer "):
#             token = auth_header.split(" ", 1)[1].strip()
#             payload = decode_token(token)
#             if not payload:
#                 return jsonify({"error": "invalid or expired token"}), 401
#             email_hash = payload.get("sub")
#             if not email_hash:
#                 return jsonify({"error": "invalid token payload"}), 401
#             user = User.query.filter_by(email_hash=email_hash).first()
#             if not user:
#                 return jsonify({"error": "user not found"}), 404
#             g.user = user
#             return fn(*args, **kwargs)

#         # Fallback: email/password in JSON body (compat mode)
#         data = request.get_json(silent=True) or {}
#         email = data.get("email")
#         password = data.get("password")
#         if not (email and password):
#             return jsonify({"error": "authorization required"}), 401
#         email_hash = sha256_hex(email.lower())
#         user = User.query.filter_by(email_hash=email_hash).first()
#         if not user or not verify_password(user.password_hash, password):
#             return jsonify({"error": "auth failed"}), 403
#         g.user = user
#         return fn(*args, **kwargs)

#     return wrapper

# # ---------------------------
# # Public endpoints
# # ---------------------------
# @api.route("/register", methods=["POST"])
# def register():
#     data = request.get_json() or {}
#     email = data.get("email")
#     password = data.get("password")
#     primary_pubkeys = data.get("primary_pubkeys", {})
#     if not email or not password:
#         return jsonify({"error": "email and password required"}), 400

#     email_hash = sha256_hex(email.lower())
#     if User.query.filter_by(email_hash=email_hash).first():
#         return jsonify({"error": "user exists"}), 400

#     pw_hash = hash_password(password)
#     user = User(email_hash=email_hash, password_hash=pw_hash, primary_pubkeys=json.dumps(primary_pubkeys))
#     db.session.add(user)
#     db.session.commit()
#     return jsonify({"status": "ok", "email_hash": email_hash}), 201

# @api.route("/login", methods=["POST"])
# def login():
#     """
#     Returns: { token: <jwt> }
#     Body: { email, password }
#     """
#     data = request.get_json() or {}
#     email = data.get("email")
#     password = data.get("password")
#     if not (email and password):
#         return jsonify({"error": "email and password required"}), 400

#     email_hash = sha256_hex(email.lower())
#     user = User.query.filter_by(email_hash=email_hash).first()
#     if not user or not verify_password(user.password_hash, password):
#         return jsonify({"error": "auth failed"}), 403

#     token = create_token(email_hash, minutes_valid=120)
#     return jsonify({"token": token}), 200

# @api.route("/keys/<email_hash>", methods=["GET"])
# def get_keys(email_hash):
#     """
#     Public: fetch public keys for a user (primary+devices).
#     """
#     user = User.query.filter_by(email_hash=email_hash).first()
#     if not user:
#         return jsonify({"error": "user not found"}), 404
#     devices = Device.query.filter_by(user_id=user.id).all()
#     devs = [{"device_id": d.device_id, "device_pubkeys": json.loads(d.device_pubkeys)} for d in devices]
#     return jsonify({"primary_pubkeys": json.loads(user.primary_pubkeys or "{}"), "devices": devs}), 200

# # ---------------------------
# # Protected endpoints (Require auth)
# # ---------------------------

# @api.route("/keys/upload", methods=["POST"])
# @auth_required
# def upload_keys():
#     """
#     Protected: Upload or update device public keys.
#     Accepts Authorization: Bearer <token> OR email/password in body (compat).
#     """
#     data = request.get_json() or {}
#     device_id = data.get("device_id")
#     device_pubkeys = data.get("device_pubkeys", {})

#     if not device_id:
#         return jsonify({"error": "device_id required"}), 400

#     user = g.user
#     # UPSERT semantics: update existing device for this user+device_id, else create
#     existing = Device.query.filter_by(user_id=user.id, device_id=device_id).first()
#     if existing:
#         existing.device_pubkeys = json.dumps(device_pubkeys)
#         existing.created_at = datetime.utcnow()
#         db.session.add(existing)
#     else:
#         dev = Device(device_id=device_id, user_id=user.id, device_pubkeys=json.dumps(device_pubkeys))
#         db.session.add(dev)

#     db.session.commit()
#     return jsonify({"status": "ok"}), 201

# @api.route("/messages/send", methods=["POST"])
# @auth_required
# def send_message():
#     data = request.get_json() or {}
#     to_hash = data.get("to_user_hash")
#     from_hash = data.get("from_user_hash")
#     payload = data.get("payload")

#     if not (to_hash and from_hash and payload):
#         return jsonify({"error": "to_user_hash, from_user_hash, payload required"}), 400

#     # Ensure authenticated user is the sender
#     if g.user and g.user.email_hash != from_hash:
#         return jsonify({"error": "sender mismatch"}), 403

#     sig_alg = payload.get("sig_alg", "ed25519")

#     # --- Signature verification for ed25519 ---
#     if sig_alg == "ed25519":
#         handshake = payload.get("handshake", {})
#         eph_b64 = handshake.get("ephemeral_x25519_pub", "")
#         nonce_b64 = payload.get("nonce", "")
#         ciphertext_b64 = payload.get("ciphertext", "")
#         aad_b64 = payload.get("aad", "")
#         sig_b64 = payload.get("signature", "")
#         from_device_id = payload.get("from_device_id", "")

#         if not sig_b64:
#             return jsonify({"error": "signature missing"}), 400

#         try:
#             # Decode fields
#             eph_raw = base64.b64decode(eph_b64) if eph_b64 else b""
#             nonce_raw = base64.b64decode(nonce_b64) if nonce_b64 else b""
#             ciphertext_raw = base64.b64decode(ciphertext_b64) if ciphertext_b64 else b""
#             aad_raw = base64.b64decode(aad_b64) if aad_b64 else b""
#             signature_raw = base64.b64decode(sig_b64)

#             # Lookup sender
#             sender_user = User.query.filter_by(email_hash=from_hash).first()
#             if not sender_user:
#                 return jsonify({"error": "sender not found"}), 404

#             # Find device row
#             device = None
#             if from_device_id:
#                 device = Device.query.filter_by(
#                     user_id=sender_user.id,
#                     device_id=from_device_id
#                 ).first()

#             if not device:
#                 # fallback to first device with an ed25519 pubkey
#                 for d in Device.query.filter_by(user_id=sender_user.id).all():
#                     try:
#                         keys = json.loads(d.device_pubkeys or "{}")
#                         if keys.get("ed25519"):
#                             device = d
#                             break
#                     except Exception:
#                         continue

#             if not device:
#                 return jsonify({"error": "sender device pubkey not found (ed25519)"}), 400

#             keys = json.loads(device.device_pubkeys or "{}")
#             ed_b64 = keys.get("ed25519")
#             if not ed_b64:
#                 return jsonify({"error": "ed25519 public key missing for device"}), 400

#             ed_raw = base64.b64decode(ed_b64)

#             # Verify signature
#             verify_input = eph_raw + nonce_raw + ciphertext_raw + aad_raw
#             signed_combo = signature_raw + verify_input
#             vk = VerifyKey(ed_raw, encoder=RawEncoder)
#             vk.verify(signed_combo)  # raises if invalid

#         except Exception as e:
#             return jsonify({
#                 "error": "signature verification failed",
#                 "detail": str(e)
#             }), 400

#     # --- Store message ---
#     msg = Message(
#         to_user_hash=to_hash,
#         from_user_hash=from_hash,
#         payload=json.dumps(payload)
#     )
#     db.session.add(msg)
#     db.session.commit()

#     return jsonify({"status": "ok", "msg_id": msg.id}), 201


# @api.route("/messages/inbox", methods=["POST"])
# @auth_required
# def inbox():
#     """
#     Protected: Fetch encrypted envelopes for authenticated user.
#     Accepts Authorization: Bearer <token> OR email/password in body (compat).
#     """
#     user = g.user
#     email_hash = user.email_hash
#     msgs = Message.query.filter_by(to_user_hash=email_hash).order_by(Message.created_at.desc()).all()
#     items = [{"id": m.id, "from": m.from_user_hash, "payload": json.loads(m.payload), "created_at": m.created_at.isoformat()} for m in msgs]
#     return jsonify({"messages": items}), 200













# backend/routes.py
from flask import Blueprint, request, jsonify, current_app, g
from backend import db
from backend.models import User, Device, Message
from backend.crypto_utils import sha256_hex, hash_password, verify_password
import json
import base64
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder
from datetime import datetime, timedelta
import jwt
from functools import wraps

api = Blueprint('api', __name__)

# ---------------------------
# JWT helpers and auth decorator
# ---------------------------
def create_token(email_hash: str, minutes_valid: int = 120) -> str:
    payload = {
        "sub": email_hash,
        "exp": datetime.utcnow() + timedelta(minutes=minutes_valid),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()
    return token

def decode_token(token: str):
    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            payload = decode_token(token)
            if not payload:
                return jsonify({"error": "invalid or expired token"}), 401
            email_hash = payload.get("sub")
            if not email_hash:
                return jsonify({"error": "invalid token payload"}), 401
            user = User.query.filter_by(email_hash=email_hash).first()
            if not user:
                return jsonify({"error": "user not found"}), 404
            g.user = user
            return fn(*args, **kwargs)

        # Fallback: email/password in JSON body
        data = request.get_json(silent=True) or {}
        email = data.get("email")
        password = data.get("password")
        if not (email and password):
            return jsonify({"error": "authorization required"}), 401
        email_hash = sha256_hex(email.lower())
        user = User.query.filter_by(email_hash=email_hash).first()
        if not user or not verify_password(user.password_hash, password):
            return jsonify({"error": "auth failed"}), 403
        g.user = user
        return fn(*args, **kwargs)

    return wrapper

# ---------------------------
# Public endpoints
# ---------------------------
@api.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    primary_pubkeys = data.get("primary_pubkeys", {})
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    email_hash = sha256_hex(email.lower())
    if User.query.filter_by(email_hash=email_hash).first():
        return jsonify({"error": "user exists"}), 400

    pw_hash = hash_password(password)
    user = User(email_hash=email_hash, password_hash=pw_hash, primary_pubkeys=json.dumps(primary_pubkeys))
    db.session.add(user)
    db.session.commit()
    return jsonify({"status": "ok", "email_hash": email_hash}), 201

@api.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not (email and password):
        return jsonify({"error": "email and password required"}), 400

    email_hash = sha256_hex(email.lower())
    user = User.query.filter_by(email_hash=email_hash).first()
    if not user or not verify_password(user.password_hash, password):
        return jsonify({"error": "auth failed"}), 403

    token = create_token(email_hash, minutes_valid=120)
    return jsonify({"token": token}), 200

@api.route("/keys/<email_hash>", methods=["GET"])
def get_keys(email_hash):
    user = User.query.filter_by(email_hash=email_hash).first()
    if not user:
        return jsonify({"error": "user not found"}), 404
    devices = Device.query.filter_by(user_id=user.id).all()
    devs = [{
        "device_id": d.device_id,
        "device_pubkeys": json.loads(d.device_pubkeys or "{}"),
        "pqc_kem_alg": d.pqc_kem_alg,
        "pqc_pubkey": d.pqc_pubkey
    } for d in devices]
    return jsonify({"primary_pubkeys": json.loads(user.primary_pubkeys or "{}"), "devices": devs}), 200

# ---------------------------
# Protected endpoints
# ---------------------------

@api.route("/keys/upload", methods=["POST"])
@auth_required
def upload_keys():
    """
    Upload or update device public keys (X25519/Ed25519 + PQC)
    """
    data = request.get_json() or {}
    device_id = data.get("device_id")
    device_pubkeys = data.get("device_pubkeys", {})

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    user = g.user
    existing = Device.query.filter_by(user_id=user.id, device_id=device_id).first()
    if existing:
        existing.device_pubkeys = json.dumps(device_pubkeys)
        existing.pqc_kem_alg = device_pubkeys.get("pqc_kem")
        existing.pqc_pubkey = device_pubkeys.get("pqc_pubkey")
        existing.created_at = datetime.utcnow()
    else:
        dev = Device(
            device_id=device_id,
            user_id=user.id,
            device_pubkeys=json.dumps(device_pubkeys),
            pqc_kem_alg=device_pubkeys.get("pqc_kem"),
            pqc_pubkey=device_pubkeys.get("pqc_pubkey")
        )
        db.session.add(dev)

    db.session.commit()
    return jsonify({"status": "ok"}), 201

@api.route("/messages/send", methods=["POST"])
@auth_required
def send_message():
    data = request.get_json() or {}
    to_hash = data.get("to_user_hash")
    from_hash = data.get("from_user_hash")
    payload = data.get("payload")

    if not (to_hash and from_hash and payload):
        return jsonify({"error": "to_user_hash, from_user_hash, payload required"}), 400

    # Ensure authenticated user is the sender
    if g.user and g.user.email_hash != from_hash:
        return jsonify({"error": "sender mismatch"}), 403

    sig_alg = payload.get("sig_alg", "ed25519")
    pqc_kem_alg = payload.get("pqc_kem_alg")
    pqc_ct = payload.get("pqc_ct")

    # ---- Signature verification for Ed25519 ----
    if sig_alg == "ed25519":
        try:
            from_device_id = payload.get("from_device_id", "")
            sender_user = User.query.filter_by(email_hash=from_hash).first()
            if not sender_user:
                return jsonify({"error": "sender not found"}), 404

            # Find sender device
            device = Device.query.filter_by(user_id=sender_user.id, device_id=from_device_id).first()
            if not device:
                # fallback: any device with ed25519
                for d in Device.query.filter_by(user_id=sender_user.id).all():
                    keys = json.loads(d.device_pubkeys or "{}")
                    if keys.get("ed25519"):
                        device = d
                        break
            if not device:
                return jsonify({"error": "sender device not found"}), 404

            keys = json.loads(device.device_pubkeys or "{}")
            ed_b64 = keys.get("ed25519")
            if not ed_b64:
                return jsonify({"error": "ed25519 key missing for device"}), 400

            ed_raw = base64.b64decode(ed_b64)
            sig_raw = base64.b64decode(payload.get("signature", "") or b"")

            eph_raw = base64.b64decode(payload.get("handshake", {}).get("ephemeral_x25519_pub", "") or b"")
            nonce_raw = base64.b64decode(payload.get("nonce", "") or b"")
            ciphertext_raw = base64.b64decode(payload.get("ciphertext", "") or b"")
            aad_raw = base64.b64decode(payload.get("aad", "") or b"")

            verify_input = eph_raw + nonce_raw + ciphertext_raw + aad_raw
            vk = VerifyKey(ed_raw, encoder=RawEncoder)
            # PyNaCl verify() expects signed_message = signature + message
            vk.verify(sig_raw + verify_input)

        except Exception as e:
            return jsonify({"error": "signature verification failed", "detail": str(e)}), 400

    elif sig_alg == "mac":
        # For MAC-based messages we don’t verify server-side (repudiable).
        pass

    elif sig_alg == "hybrid":
        # For hybrid PQC + X25519 messages we currently skip signature verification.
        # They rely on confidentiality only.
        pass

    else:
        return jsonify({"error": f"unknown sig_alg {sig_alg}"}), 400

    # ---- Store message ----
    msg = Message(
        to_user_hash=to_hash,
        from_user_hash=from_hash,
        payload=json.dumps(payload),
        pqc_kem_alg=pqc_kem_alg,
        pqc_ct=pqc_ct
    )
    db.session.add(msg)
    db.session.commit()

    return jsonify({"status": "ok", "msg_id": msg.id}), 201

@api.route("/messages/inbox", methods=["POST"])
@auth_required
def inbox():
    """
    Fetch all messages for the authenticated user.
    """
    user = g.user
    msgs = Message.query.filter_by(to_user_hash=user.email_hash).order_by(Message.created_at.desc()).all()
    items = [{
        "id": m.id,
        "from": m.from_user_hash,
        "payload": json.loads(m.payload),
        "created_at": m.created_at.isoformat(),
        "pqc_kem_alg": m.pqc_kem_alg,
        "pqc_ct": m.pqc_ct
    } for m in msgs]
    return jsonify({"messages": items}), 200
