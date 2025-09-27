"""
client_demo.py  (Ed25519 signing variant, robust & auto-reupload)

- Registers Alice & Bob (tolerant if they already exist)
- Uploads device pubkeys (x25519 + ed25519)
- Alice creates ephemeral x25519 key, ECDH -> derive AEAD key, encrypts
- Alice signs (ed25519) the handshake/ciphertext envelope
- Alice sends envelope to server
- Bob fetches envelope, retrieves Alice's ed25519 pubkey (by device_id),
  verifies signature, then decrypts if signature valid.
- If Alice's ed25519 is missing on the server, the client auto re-uploads
  Alice's device keys (using the in-memory keys) and retries verification.

Run:
    python client_demo.py
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

# PyNaCl for Ed25519 signing
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder

API_BASE = "http://127.0.0.1:5000/api"

# -------- helpers ----------

# Add these imports near the top if not already present:
# from nacl.signing import SigningKey
# from nacl.encoding import RawEncoder
# from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def ensure_keys_for_user(prefix: str):
    """
    Ensure (and persist) X25519 + Ed25519 keypairs for a user prefix (e.g. 'alice' or 'bob').
    Returns: (x25519_priv_obj, x25519_pub_raw_bytes, SigningKey_obj, ed25519_pub_raw_bytes)
    Writes raw bytes into keys/<prefix>_*.raw
    """
    os.makedirs("keys", exist_ok=True)
    x_priv_file = f"keys/{prefix}_x25519_priv.raw"
    x_pub_file  = f"keys/{prefix}_x25519_pub.raw"
    ed_priv_file = f"keys/{prefix}_ed25519_priv.raw"
    ed_pub_file  = f"keys/{prefix}_ed25519_pub.raw"

    # X25519: load or generate
    if os.path.exists(x_priv_file) and os.path.exists(x_pub_file):
        xpriv_raw = open(x_priv_file, "rb").read()
        xpub_raw = open(x_pub_file, "rb").read()
        xpriv = X25519PrivateKey.from_private_bytes(xpriv_raw)
        # xpub object not strictly needed, but can be created:
        # xpub = X25519PublicKey.from_public_bytes(xpub_raw)
    else:
        xpriv = X25519PrivateKey.generate()
        xpriv_raw = xpriv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        xpub_raw = xpriv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        open(x_priv_file, "wb").write(xpriv_raw)
        open(x_pub_file, "wb").write(xpub_raw)

    # Ed25519 signing key (PyNaCl): load or generate
    if os.path.exists(ed_priv_file) and os.path.exists(ed_pub_file):
        ed_priv_raw = open(ed_priv_file, "rb").read()
        ed_pub_raw = open(ed_pub_file, "rb").read()
        sign_sk = SigningKey(ed_priv_raw, encoder=RawEncoder)
    else:
        sign_sk = SigningKey.generate()
        ed_priv_raw = sign_sk.encode(encoder=RawEncoder)   # 32 bytes
        ed_pub_raw = sign_sk.verify_key.encode(encoder=RawEncoder)
        open(ed_priv_file, "wb").write(ed_priv_raw)
        open(ed_pub_file, "wb").write(ed_pub_raw)

    return xpriv, xpub_raw, sign_sk, ed_pub_raw


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

# Note: ChaCha20-Poly1305 expects a 12-byte nonce
def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, aad)

# -------- server wrappers ----------
def register_user(email: str, password: str, primary_pubkeys: dict = None):
    payload = {"email": email, "password": password, "primary_pubkeys": primary_pubkeys or {}}
    r = requests.post(f"{API_BASE}/register", json=payload)
    # tolerant: if user exists (400), compute and return email_hash locally
    if r.status_code == 201:
        return r.json()
    if r.status_code == 400:
        try:
            resp = r.json()
            if "email_hash" in resp:
                return resp
        except Exception:
            pass
        return {"email_hash": sha256_hex(email)}
    r.raise_for_status()

def upload_device_keys(email: str, password: str, device_id: str, device_pubkeys: dict):
    payload = {"email": email, "password": password, "device_id": device_id, "device_pubkeys": device_pubkeys}
    r = requests.post(f"{API_BASE}/keys/upload", json=payload)
    r.raise_for_status()
    return r.json()

def fetch_keys(email_hash: str):
    r = requests.get(f"{API_BASE}/keys/{email_hash}")
    r.raise_for_status()
    return r.json()

def send_message(to_hash: str, from_hash: str, payload: dict):
    data = {"to_user_hash": to_hash, "from_user_hash": from_hash, "payload": payload}
    r = requests.post(f"{API_BASE}/messages/send", json=data)
    r.raise_for_status()
    return r.json()

def fetch_inbox(email: str, password: str):
    data = {"email": email, "password": password}
    r = requests.post(f"{API_BASE}/messages/inbox", json=data)
    r.raise_for_status()
    return r.json()

# -------- demo flow ----------
def demo():
    print("[*] Starting signed-client demo. Make sure server is running at", API_BASE)

    # User creds
    alice_email = "alice@example.com"
    alice_pw = "AlicePass1!"
    bob_email = "bob@example.com"
    bob_pw = "BobPass1!"

    print("[*] Registering users (tolerant to existing users)...")
    alice_reg = register_user(alice_email, alice_pw)
    bob_reg = register_user(bob_email, bob_pw)
    print("  alice hash:", alice_reg["email_hash"])
    print("  bob hash:", bob_reg["email_hash"])

    # Generate static keypairs for both (simulate device keys)
    print("[*] Generating (or loading) static X25519 + Ed25519 keypairs for Alice & Bob (client-side)...")
    # ensure_keys_for_user returns: (xpriv, xpub_raw, sign_sk, ed_pub_raw)
    alice_priv, alice_pub_raw, alice_sign_sk, alice_sign_pk_raw = ensure_keys_for_user("alice")
    alice_pub = X25519PublicKey.from_public_bytes(alice_pub_raw)

    bob_priv, bob_pub_raw, bob_sign_sk, bob_sign_pk_raw = ensure_keys_for_user("bob")
    bob_pub = X25519PublicKey.from_public_bytes(bob_pub_raw)


    # Upload device keys to server (Base64 encoded raw pubkey)
    print("[*] Uploading device public keys to server (x25519 + ed25519)...")
    alice_device_id = "alice-web-01"
    bob_device_id = "bob-web-01"
    alice_pub_b64 = b64enc(alice_pub_raw)
    bob_pub_b64 = b64enc(bob_pub_raw)
    alice_ed25519_b64 = b64enc(alice_sign_pk_raw)
    bob_ed25519_b64 = b64enc(bob_sign_pk_raw)

    upload_device_keys(alice_email, alice_pw, alice_device_id, {"x25519": alice_pub_b64, "ed25519": alice_ed25519_b64})
    upload_device_keys(bob_email, bob_pw, bob_device_id, {"x25519": bob_pub_b64, "ed25519": bob_ed25519_b64})
    print("  uploaded keys.")

    # Alice fetches Bob's public keys from server (to prepare send)
    bob_hash = bob_reg["email_hash"]
    print("[*] Fetching Bob's keys...")
    bob_keys = fetch_keys(bob_hash)
    bob_devices = bob_keys.get("devices", [])
    if not bob_devices:
        raise RuntimeError("No Bob devices found on server")
    bob_x25519_b64 = bob_devices[0]["device_pubkeys"]["x25519"]
    bob_x25519_raw = b64dec(bob_x25519_b64)
    bob_x25519_pub = X25519PublicKey.from_public_bytes(bob_x25519_raw)

    # Alice creates ephemeral key, performs ECDH with Bob's static pub
    print("[*] Alice creates ephemeral X25519 and performs ECDH with Bob's static pub...")
    alice_eph_priv = X25519PrivateKey.generate()
    alice_eph_pub = alice_eph_priv.public_key()
    alice_eph_pub_raw = alice_eph_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    shared_secret = alice_eph_priv.exchange(bob_x25519_pub)  # bytes
    aead_key = derive_aead_key(shared_secret, info=b"stegmail-demo")
    print("  derived AEAD key (len={} bytes)".format(len(aead_key)))

    # Alice encrypts a message
    plaintext = b"Hello Bob! This is Alice. Signed with Ed25519 and encrypted."
    aad = b"stegmail-v1"  # optional
    nonce, ciphertext = aead_encrypt(aead_key, plaintext, aad)
    print("  encrypted message (ciphertext len {})".format(len(ciphertext)))

    # Alice computes signature over (ephemeral_pub || nonce || ciphertext || aad)
    to_sign = alice_eph_pub_raw + nonce + ciphertext + aad
    signed = alice_sign_sk.sign(to_sign)   # signed.message = original message; signed.signature available
    signature = signed.signature  # 64 bytes
    sig_b64 = b64enc(signature)

    # Build envelope (include from_device_id so receiver can find correct pubkey)
    envelope = {
        "version": "1",
        "handshake": {
            "ephemeral_x25519_pub": b64enc(alice_eph_pub_raw),
        },
        "ratchet": {
            "counter": 1
        },
        "from_device_id": alice_device_id,
        "aad": b64enc(aad),
        "nonce": b64enc(nonce),
        "ciphertext": b64enc(ciphertext),
        "signature": sig_b64,
        "sig_alg": "ed25519"
    }

    # Alice sends envelope to Bob (server stores it opaque)
    alice_hash = alice_reg["email_hash"]
    send_res = send_message(to_hash=bob_hash, from_hash=alice_hash, payload=envelope)
    print("  message stored on server id:", send_res.get("msg_id"))

    time.sleep(1)  # tiny wait for realism

    # Bob fetches inbox and verifies signature before decrypting
    print("[*] Bob fetching inbox...")
    inbox = fetch_inbox(bob_email, bob_pw)
    messages = inbox.get("messages", [])
    if not messages:
        raise RuntimeError("No messages found in Bob's inbox")
    # pick the latest message
    msg = messages[0]
    payload = msg["payload"]
    print("  fetched message id:", msg["id"], "from:", msg["from"])

    # Extract envelope fields
    eph_pub_b64 = payload["handshake"]["ephemeral_x25519_pub"]
    nonce_b64 = payload["nonce"]
    ciphertext_b64 = payload["ciphertext"]
    aad_b64 = payload.get("aad", "")
    sig_b64 = payload.get("signature", "")
    from_device_id = payload.get("from_device_id", "")

    eph_pub_raw = b64dec(eph_pub_b64)
    nonce_raw = b64dec(nonce_b64)
    ciphertext_raw = b64dec(ciphertext_b64)
    aad_raw = b64dec(aad_b64) if aad_b64 else b""
    signature_raw = b64dec(sig_b64) if sig_b64 else b""

    # Bob needs Alice's ed25519 pubkey to verify signature.
    alice_hash = msg["from"]

    # Fetch keys and attempt to find ed25519 for the device. If missing, auto-reupload.
    alice_keys = fetch_keys(alice_hash)
    alice_devs = alice_keys.get("devices", [])

    # Try to find device by from_device_id with ed25519
    alice_dev_pub = None
    for d in alice_devs:
        if d.get("device_id") == from_device_id and d.get("device_pubkeys", {}).get("ed25519"):
            alice_dev_pub = d["device_pubkeys"]
            break

    # If not found, search any device with ed25519
    if alice_dev_pub is None:
        for d in alice_devs:
            if d.get("device_pubkeys", {}).get("ed25519"):
                alice_dev_pub = d["device_pubkeys"]
                print("  Note: using ed25519 pubkey from device_id:", d.get("device_id"))
                break

    # If still not found, auto-reupload Alice's device keys (using the in-memory keys we created earlier)
    if alice_dev_pub is None:
        print("  Alice's ed25519 pubkey not found on server for any device. Auto re-uploading Alice's device entry...")
        try:
            # Re-upload using same device_id and keys generated earlier
            upload_device_keys(alice_email, alice_pw, alice_device_id, {
                "x25519": b64enc(alice_pub_raw),
                "ed25519": b64enc(alice_sign_pk_raw)
            })
            # re-fetch keys and select the newly uploaded device (search by device_id)
            alice_keys = fetch_keys(alice_hash)
            alice_devs = alice_keys.get("devices", [])
            for d in alice_devs:
                if d.get("device_id") == alice_device_id and d.get("device_pubkeys", {}).get("ed25519"):
                    alice_dev_pub = d["device_pubkeys"]
                    print("  Successfully re-uploaded Alice's device pubkeys.")
                    break
        except Exception as e:
            print("  Auto re-upload failed:", str(e))
            print("  Debug devices:", alice_devs)
            raise RuntimeError("Alice's ed25519 pubkey missing on server and auto-reupload failed.")

    if alice_dev_pub is None:
        # final fallback failure
        print("  Debug devices:", alice_devs)
        raise RuntimeError("Alice's ed25519 pubkey missing on server after retry.")

    alice_ed25519_b64 = alice_dev_pub.get("ed25519")
    alice_ed25519_raw = b64dec(alice_ed25519_b64)

    # Verify signature: verify (ephemeral_pub_raw || nonce_raw || ciphertext_raw || aad_raw)
    verify_input = eph_pub_raw + nonce_raw + ciphertext_raw + aad_raw
    signed_combo = signature_raw + verify_input  # PyNaCl VerifyKey expects signature+message format
    try:
        vk = VerifyKey(alice_ed25519_raw, encoder=RawEncoder)
        vk.verify(signed_combo)  # raises if invalid
        print("  Signature verification: OK (message authentic)")
    except Exception as e:
        print("  Signature verification FAILED:", str(e))
        print("  Aborting decryption.")
        return

    # If signature verifies, perform ECDH & decrypt
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
    shared_secret_bob = bob_priv.exchange(eph_pub)
    aead_key_bob = derive_aead_key(shared_secret_bob, info=b"stegmail-demo")

    decrypted = aead_decrypt(aead_key_bob, nonce_raw, ciphertext_raw, aad_raw)
    print("  Bob decrypted message:", decrypted.decode())

if __name__ == "__main__":
    demo()
