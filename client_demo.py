"""
client_demo.py

Demo client test harness for the StegMail prototype backend.

This variant uses ChaCha20-Poly1305 (12-byte nonce) from cryptography so it works
with more cryptography builds on Windows.

Flow:
 - Register two users (alice, bob)
 - Upload each user's X25519 public key as device_pubkeys
 - Alice encrypts a message to Bob using ephemeral X25519 -> HKDF -> ChaCha20-Poly1305
 - Alice POSTs envelope to /api/messages/send
 - Bob fetches /api/messages/inbox and decrypts

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
    r.raise_for_status()
    return r.json()

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
    print("[*] Starting client demo. Make sure server is running at", API_BASE)

    # User creds
    alice_email = "alice@example.com"
    alice_pw = "AlicePass1!"
    bob_email = "bob@example.com"
    bob_pw = "BobPass1!"

    print("[*] Registering users...")
    alice_reg = register_user(alice_email, alice_pw)
    bob_reg = register_user(bob_email, bob_pw)
    print("  alice hash:", alice_reg["email_hash"])
    print("  bob hash:", bob_reg["email_hash"])

    # Generate static keypairs for both (simulate device keys)
    print("[*] Generating static X25519 keypairs for Alice & Bob (client-side)...")
    alice_priv, alice_pub, alice_priv_raw, alice_pub_raw = gen_x25519_keypair()
    bob_priv, bob_pub, bob_priv_raw, bob_pub_raw = gen_x25519_keypair()

    # Upload device keys to server (Base64 encoded raw pubkey)
    print("[*] Uploading device public keys to server...")
    alice_device_id = "alice-web-01"
    bob_device_id = "bob-web-01"
    alice_pub_b64 = b64enc(alice_pub_raw)
    bob_pub_b64 = b64enc(bob_pub_raw)

    upload_device_keys(alice_email, alice_pw, alice_device_id, {"x25519": alice_pub_b64})
    upload_device_keys(bob_email, bob_pw, bob_device_id, {"x25519": bob_pub_b64})
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
    plaintext = b"Hello Bob! This is Alice. Testing E2E via ephemeral X25519 (ChaCha20-Poly1305)."
    aad = b"stegmail-v1"  # optional
    nonce, ciphertext = aead_encrypt(aead_key, plaintext, aad)
    print("  encrypted message (ciphertext len {})".format(len(ciphertext)))

    # Build envelope
    envelope = {
        "version": "1",
        "handshake": {
            "ephemeral_x25519_pub": b64enc(alice_eph_pub_raw),
        },
        "ratchet": {
            "counter": 1
        },
        "aad": b64enc(aad),
        "nonce": b64enc(nonce),
        "ciphertext": b64enc(ciphertext)
    }

    # Alice sends envelope to Bob (server stores it opaque)
    alice_hash = alice_reg["email_hash"]
    send_res = send_message(to_hash=bob_hash, from_hash=alice_hash, payload=envelope)
    print("  message stored on server id:", send_res.get("msg_id"))

    time.sleep(1)  # tiny wait for realism

    # Bob fetches inbox and decrypts
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

    eph_pub_raw = b64dec(eph_pub_b64)
    nonce_raw = b64dec(nonce_b64)
    ciphertext_raw = b64dec(ciphertext_b64)
    aad_raw = b64dec(aad_b64) if aad_b64 else b""

    # Bob does ECDH: his static priv (bob_priv) with alice ephemeral pub
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
    shared_secret_bob = bob_priv.exchange(eph_pub)
    aead_key_bob = derive_aead_key(shared_secret_bob, info=b"stegmail-demo")

    # Decrypt
    decrypted = aead_decrypt(aead_key_bob, nonce_raw, ciphertext_raw, aad_raw)
    print("  Bob decrypted message:", decrypted.decode())

if __name__ == "__main__":
    demo()
