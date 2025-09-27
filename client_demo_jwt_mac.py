"""
client_demo_jwt_mac.py

Demonstrates:
 - JWT-based login (token)
 - Uploading device pubkeys with Authorization: Bearer <token>
 - Sending two messages:
    1) Non-repudiable: Ed25519 signature over envelope fields
    2) Repudiable: HMAC-SHA256 (MAC) derived from ECDH -> HKDF (repudiable because MAC key is shared)
 - Bob fetches inbox (using token) and verifies/decrypts messages.

Run:
    python client_demo_jwt_mac.py
"""
import requests
import base64
import json
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib
import os
import time
import hmac
from datetime import datetime, timezone
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from nacl.public import PrivateKey
from nacl.signing import SigningKey
import oqs
from pathlib import Path

API_BASE = "http://127.0.0.1:5000/api"

# -------- helpers ----------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode())

def gen_x25519_keypair():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return priv, pub, priv_raw, pub_raw

def derive_aead_key(shared_secret: bytes, info: bytes = b"stegmail-demo") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared_secret)

def derive_mac_key(shared_secret: bytes, info: bytes = b"stegmail-mac") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared_secret)

# ChaCha20-Poly1305 uses 12-byte nonce
def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, aad)

# Key persistence helper (same as before)
def ensure_keys_for_user(prefix: str):
    os.makedirs("keys", exist_ok=True)
    x_priv_file = f"keys/{prefix}_x25519_priv.raw"
    x_pub_file  = f"keys/{prefix}_x25519_pub.raw"
    ed_priv_file = f"keys/{prefix}_ed25519_priv.raw"
    ed_pub_file  = f"keys/{prefix}_ed25519_pub.raw"

    if os.path.exists(x_priv_file) and os.path.exists(x_pub_file):
        xpriv_raw = open(x_priv_file, "rb").read()
        xpub_raw = open(x_pub_file, "rb").read()
        xpriv = X25519PrivateKey.from_private_bytes(xpriv_raw)
    else:
        xpriv = X25519PrivateKey.generate()
        xpriv_raw = xpriv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        xpub_raw = xpriv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        open(x_priv_file, "wb").write(xpriv_raw)
        open(x_pub_file, "wb").write(xpub_raw)

    if os.path.exists(ed_priv_file) and os.path.exists(ed_pub_file):
        ed_priv_raw = open(ed_priv_file, "rb").read()
        ed_pub_raw = open(ed_pub_file, "rb").read()
        sign_sk = SigningKey(ed_priv_raw, encoder=RawEncoder)
    else:
        sign_sk = SigningKey.generate()
        ed_priv_raw = sign_sk.encode(encoder=RawEncoder)
        ed_pub_raw = sign_sk.verify_key.encode(encoder=RawEncoder)
        open(ed_priv_file, "wb").write(ed_priv_raw)
        open(ed_pub_file, "wb").write(ed_pub_raw)

    return xpriv, xpub_raw, sign_sk, ed_pub_raw


API_BASE = "http://127.0.0.1:5000/api"
ALICE_EMAIL = "alice@example.com"
ALICE_PASSWORD = "alicepass"

# -------- server wrappers (with Authorization header) ----------

def login(email: str, password: str) -> str:
    r = requests.post(f"{API_BASE}/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()["token"]

def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

def upload_device_keys(device_id: str, device_pubkeys: dict, token: str):
    headers = auth_headers(token)
    payload = {"device_id": device_id, "device_pubkeys": device_pubkeys}
    r = requests.post(f"{API_BASE}/keys/upload", json=payload, headers=headers)
    r.raise_for_status()
    return r.json()

# --- login and upload keys ---

print("[*] Logging in...")
token = login(ALICE_EMAIL, ALICE_PASSWORD)

print("[*] Generating keys...")
x25519_sk = PrivateKey.generate()
x25519_pk = bytes(x25519_sk.public_key)

ed_sk = SigningKey.generate()
ed_pk = bytes(ed_sk.verify_key)

with oqs.KeyEncapsulation("Kyber768") as kem:
    pqc_pk = kem.generate_keypair()

device_keys = {
    "x25519": base64.b64encode(x25519_pk).decode(),
    "ed25519": base64.b64encode(ed_pk).decode(),
    "pqc_kem": "Kyber768",
    "pqc_pubkey": base64.b64encode(pqc_pk).decode()
}

print("[*] Uploading device keys...")
resp = upload_device_keys("alice-desktop-01", device_keys, token)
print("Upload response:", resp)


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

def upload_device_keys(email: str, password: str, device_id: str, device_pubkeys: dict, token: str = None):
    headers = auth_headers(token) if token else {}
    payload = {"device_id": device_id, "device_pubkeys": device_pubkeys}
    # We use POST to protected endpoint; token in header.
    r = requests.post(f"{API_BASE}/keys/upload", json={"device_id": device_id, "device_pubkeys": device_pubkeys}, headers=headers)
    r.raise_for_status()
    return r.json()

def fetch_keys(email_hash: str):
    r = requests.get(f"{API_BASE}/keys/{email_hash}")
    r.raise_for_status()
    return r.json()

def send_message(to_hash: str, from_hash: str, payload: dict, token: str = None):
    headers = auth_headers(token) if token else {}
    data = {"to_user_hash": to_hash, "from_user_hash": from_hash, "payload": payload}
    r = requests.post(f"{API_BASE}/messages/send", json=data, headers=headers)

    if r.status_code != 201:
        print("[!] Server rejected message:", r.status_code)
        try:
            print("[!] Response JSON:", r.json())
        except Exception:
            print("[!] Response text:", r.text)
        return None   # IMPORTANT: don't call r.raise_for_status()

    return r.json()


def fetch_inbox(email: str, password: str = None, token: str = None):
    headers = auth_headers(token) if token else {}
    if token:
        r = requests.post(f"{API_BASE}/messages/inbox", json={}, headers=headers)
    else:
        r = requests.post(f"{API_BASE}/messages/inbox", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()

def save_inbox_to_file(history):
    out_path = Path("data/inbox_bob.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Load old data if exists
    if out_path.exists():
        try:
            with open(out_path, "r") as f:
                old_data = json.load(f)
        except Exception:
            old_data = {"messages": []}
    else:
        old_data = {"messages": []}

    # Merge new messages
    all_messages = old_data.get("messages", [])
    all_messages.extend(history)

    # Optionally deduplicate by message id
    unique_messages = {msg["id"]: msg for msg in all_messages}.values()

    data = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "messages": list(unique_messages)
    }

    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print("[*] Saved inbox to", out_path)


# HMAC helper
def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()


def demo():
    print("[*] JWT + MAC demo starting. Server:", API_BASE)

    # credentials
    alice_email = "alice@example.com"
    alice_pw = "AlicePass1!"
    bob_email = "bob@example.com"
    bob_pw = "BobPass1!"

    # Register tolerant (server may already have users)
    def register_user(email, password):
        try:
            r = requests.post(f"{API_BASE}/register", json={"email": email, "password": password})
            if r.status_code in (200, 201):
                return r.json()
        except Exception:
            pass
        return {"email_hash": sha256_hex(email)}

    print("[*] Registering users (tolerant)...")
    alice_reg = register_user(alice_email, alice_pw)
    bob_reg = register_user(bob_email, bob_pw)
    alice_hash = alice_reg["email_hash"]
    bob_hash = bob_reg["email_hash"]
    print("  alice:", alice_hash)
    print("  bob  :", bob_hash)

    # login to obtain tokens
    print("[*] Logging in to obtain tokens...")
    alice_token = login(alice_email, alice_pw)
    bob_token = login(bob_email, bob_pw)
    print("  alice token len:", len(alice_token))
    print("  bob token len:  ", len(bob_token))

    # load persistent keys for both users
    print("[*] Loading or generating keypairs for Alice & Bob...")
    alice_priv, alice_pub_raw, alice_sign_sk, alice_sign_pk_raw = ensure_keys_for_user("alice")
    alice_pub = X25519PublicKey.from_public_bytes(alice_pub_raw)

    bob_priv, bob_pub_raw, bob_sign_sk, bob_sign_pk_raw = ensure_keys_for_user("bob")
    bob_pub = X25519PublicKey.from_public_bytes(bob_pub_raw)

    # Upload device keys
    alice_device_id = "alice-web-01"
    bob_device_id = "bob-web-01"
    upload_device_keys(alice_email, alice_pw, alice_device_id,
                       {"x25519": b64enc(alice_pub_raw), "ed25519": b64enc(alice_sign_pk_raw)},
                       token=alice_token)
    upload_device_keys(bob_email, bob_pw, bob_device_id,
                       {"x25519": b64enc(bob_pub_raw), "ed25519": b64enc(bob_sign_pk_raw)},
                       token=bob_token)
    print("  uploaded device keys (with JWT)")

    # fetch Bob's x25519 pubkey
    bob_keys = fetch_keys(bob_hash)
    bob_devices = bob_keys.get("devices", [])
    if not bob_devices:
        raise RuntimeError("No Bob devices")
    bob_x25519_b64 = bob_devices[0]["device_pubkeys"]["x25519"]
    bob_x25519_raw = b64dec(bob_x25519_b64)
    bob_x25519_pub = X25519PublicKey.from_public_bytes(bob_x25519_raw)

    # ---------- SEND MESSAGE 1: Ed25519 signature ----------
    print("[*] Preparing Message 1 (Ed25519 signed)...")
    alice_eph_priv = X25519PrivateKey.generate()
    alice_eph_pub_raw = alice_eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    shared_secret = alice_eph_priv.exchange(bob_x25519_pub)
    aead_key = derive_aead_key(shared_secret, info=b"stegmail-demo")
    nonce, ciphertext = aead_encrypt(aead_key, b"Hello Bob - msg1 (signed)", aad=b"v1")

    # signature
    to_sign = alice_eph_pub_raw + nonce + ciphertext + b"v1"
    signature = alice_sign_sk.sign(to_sign).signature
    envelope1 = {
        "version": "1",
        "handshake": {"ephemeral_x25519_pub": b64enc(alice_eph_pub_raw)},
        "from_device_id": alice_device_id,
        "aad": b64enc(b"v1"),
        "nonce": b64enc(nonce),
        "ciphertext": b64enc(ciphertext),
        "signature": b64enc(signature),
        "sig_alg": "ed25519"
    }
    send_message(bob_hash, alice_hash, envelope1, token=alice_token)
    print("  sent message 1 (ed25519)")

    # ---------- SEND MESSAGE 2: MAC ----------
    print("[*] Preparing Message 2 (MAC-based, repudiable)...")
    alice_eph_priv2 = X25519PrivateKey.generate()
    alice_eph_pub_raw2 = alice_eph_priv2.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    shared_secret2 = alice_eph_priv2.exchange(bob_x25519_pub)
    aead_key2 = derive_aead_key(shared_secret2, info=b"stegmail-demo")
    nonce2, ciphertext2 = aead_encrypt(aead_key2, b"Hello Bob - msg2 (MAC)", aad=b"v1")

    mac_key = derive_mac_key(shared_secret2, info=b"stegmail-mac")
    mac_input = alice_eph_pub_raw2 + nonce2 + ciphertext2 + b"v1"
    mac_tag = compute_hmac_sha256(mac_key, mac_input)

    envelope2 = {
        "version": "1",
        "handshake": {"ephemeral_x25519_pub": b64enc(alice_eph_pub_raw2)},
        "from_device_id": alice_device_id,
        "aad": b64enc(b"v1"),
        "nonce": b64enc(nonce2),
        "ciphertext": b64enc(ciphertext2),
        "signature": b64enc(mac_tag),
        "sig_alg": "mac"
    }
    send_message(bob_hash, alice_hash, envelope2, token=alice_token)
    print("  sent message 2 (mac)")

    # ---------- SEND MESSAGE 3: Hybrid X25519 + Kyber768 ----------
    print("[*] Preparing Message 3 (Hybrid PQC + X25519)...")
    # 1) ephemeral X25519
    alice_eph_priv3 = X25519PrivateKey.generate()
    alice_eph_pub_raw3 = alice_eph_priv3.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    ss_x25519 = alice_eph_priv3.exchange(bob_x25519_pub)

    # 2) Kyber768 encapsulation
    with oqs.KeyEncapsulation("Kyber768") as kem:
        # --- fetch Bob's PQC pubkey ---
        bob_devices = bob_keys.get("devices", [])
        bob_pqc_pub_b64 = bob_devices[0]["device_pubkeys"].get("pqc_pubkey")
        if not bob_pqc_pub_b64:
            raise RuntimeError("Bob device does not have pqc_pubkey")
        kem.import_public_key(base64.b64decode(bob_pqc_pub_b64))
        ct_pqc, ss_pqc = kem.encap_secret()

    # 3) Combine secrets with HKDF
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-session-key")
    hybrid_key = hkdf.derive(ss_x25519 + ss_pqc)

    # 4) Encrypt message
    nonce3 = os.urandom(12)
    aad3 = b"hybrid-v1"
    aead = ChaCha20Poly1305(hybrid_key)
    ciphertext3 = aead.encrypt(nonce3, b"Hello Bob - msg3 (Hybrid PQC+X25519)", aad3)

    # 5) Create envelope
    envelope3 = {
        "version": "1",
        "handshake": {
            "ephemeral_x25519_pub": b64enc(alice_eph_pub_raw3)
        },
        "from_device_id": alice_device_id,
        "aad": b64enc(aad3),
        "nonce": b64enc(nonce3),
        "ciphertext": b64enc(ciphertext3),
        "pqc_kem_alg": "Kyber768",
        "pqc_ct": b64enc(ct_pqc),
        "sig_alg": "hybrid"
    }

    send_message(bob_hash, alice_hash, envelope3, token=alice_token)
    print("  sent message 3 (hybrid)")


    time.sleep(1)

    # ---------- BOB FETCHES INBOX ----------
    print("[*] Bob fetching inbox (using his JWT)...")
    inbox = fetch_inbox(bob_email, token=bob_token)
    messages = inbox.get("messages", [])
    if not messages:
        print("No messages")
        return

    history = []  # collect decrypted history

    for msg in messages:
        print("----")
        print("Message id:", msg["id"], "from:", msg["from"])
        payload = msg["payload"]
        eph_pub_raw = b64dec(payload["handshake"]["ephemeral_x25519_pub"])
        nonce_raw = b64dec(payload["nonce"])
        ciphertext_raw = b64dec(payload["ciphertext"])
        aad_raw = b64dec(payload.get("aad", "")) if payload.get("aad") else b""
        signature_raw = b64dec(payload.get("signature", "")) if payload.get("signature") else b""
        sig_alg = payload.get("sig_alg", "ed25519")
        from_device_id = payload.get("from_device_id", "")

        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
        shared_secret_bob = bob_priv.exchange(eph_pub)
        aead_key_bob = derive_aead_key(shared_secret_bob, info=b"stegmail-demo")

        decrypted_text = None

        if sig_alg == "ed25519":
            sender_hash = msg["from"]
            sender_keys = fetch_keys(sender_hash)
            sender_devs = sender_keys.get("devices", [])
            sender_dev = next((d for d in sender_devs
                               if d.get("device_id") == from_device_id and d.get("device_pubkeys", {}).get("ed25519")), None)
            if not sender_dev:
                sender_dev = next((d for d in sender_devs if d.get("device_pubkeys", {}).get("ed25519")), None)
            if sender_dev:
                ed25519_raw = b64dec(sender_dev["device_pubkeys"]["ed25519"])
                verify_input = eph_pub_raw + nonce_raw + ciphertext_raw + aad_raw
                signed_combo = signature_raw + verify_input
                try:
                    vk = VerifyKey(ed25519_raw, encoder=RawEncoder)
                    vk.verify(signed_combo)
                    print("  Signature OK (ed25519). Decrypting...")
                    decrypted = aead_decrypt(aead_key_bob, nonce_raw, ciphertext_raw, aad_raw)
                    decrypted_text = decrypted.decode()
                    print("  Decrypted plaintext:", decrypted_text)
                except Exception as e:
                    print("  Signature verification FAILED:", str(e))
            else:
                print("  No sender ed25519 pubkey; cannot verify")

        elif sig_alg == "mac":
            mac_key_bob = derive_mac_key(shared_secret_bob, info=b"stegmail-mac")
            mac_input = eph_pub_raw + nonce_raw + ciphertext_raw + aad_raw
            expected_mac = compute_hmac_sha256(mac_key_bob, mac_input)
            if hmac.compare_digest(expected_mac, signature_raw):
                print("  MAC OK (repudiable). Decrypting...")
                try:
                    decrypted = aead_decrypt(aead_key_bob, nonce_raw, ciphertext_raw, aad_raw)
                    decrypted_text = decrypted.decode()
                    print("  Decrypted plaintext:", decrypted_text)
                except Exception as e:
                    print("  Decrypt failed:", str(e))
            else:
                print("  MAC verification FAILED")
        else:
            print("  Unknown sig_alg:", sig_alg)

        # Record message into history if decrypted
        history.append({
            "id": msg["id"],
            "from": msg["from"],
            "created_at": msg.get("created_at"),
            "sig_alg": sig_alg,
            "aad": payload.get("aad", ""),
            "ciphertext": payload.get("ciphertext", ""),
            "decrypted_text": decrypted_text or "<not decrypted>"
        })

    # Save inbox history to file
    save_inbox_to_file(history)

if __name__ == "__main__":
    demo()
